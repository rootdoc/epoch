%%%=============================================================================
%%% @copyright (C) 2018, Aeternity Anstalt
%%% @doc
%%%    State Channel utility functions
%%% @end
%%%=============================================================================
-module(aesc_utils).

%% API
-export([get_channel/2,
         accounts_in_poi/2,
         check_is_active/1,
         check_is_peer/2,
         check_are_funds_in_channel/3,
         check_round_greater_than_last/2,
         check_state_hash_size/1,
         deserialize_payload/1,
         check_solo_close_payload/7,
         check_slash_payload/8,
         check_solo_snapshot_payload/6,
         check_force_progress/11,
         process_solo_close/8,
         process_slash/8,
         process_force_progress/11,
         process_solo_snapshot/6
        ]).

%%%===================================================================
%%% API
%%%===================================================================

-spec get_channel(aesc_channels:id(), aec_trees:trees()) ->
                         {error, term()} | ok.
get_channel(ChannelId, Trees) ->
    ChannelsTree = aec_trees:channels(Trees),
    case aesc_state_tree:lookup(ChannelId, ChannelsTree) of
        none ->
            {error, channel_does_not_exist};
        {value, Ch} ->
            {ok, Ch}
    end.

accounts_in_poi(Peers, PoI) ->
    Lookups = [aec_trees:lookup_poi(accounts, Pubkey, PoI) || Pubkey <- Peers],
    Accounts = [Acc || {ok, Acc} <- Lookups], % filter successful ones
    case length(Accounts) =:= length(Peers) of
        false -> {error, wrong_channel_peers};
        true ->
            {ok, Accounts}
    end.

-spec check_is_active(aesc_channels:channel()) -> ok | {error, channel_not_active}.
check_is_active(Channel) ->
    case aesc_channels:is_active(Channel) of
        true  -> ok;
        false -> {error, channel_not_active}
    end.

check_is_closing(Channel, Height) ->
    case aesc_channels:is_solo_closing(Channel, Height) of
        true  -> ok;
        false -> {error, channel_not_closing}
    end.

-spec check_round_greater_than_last(aesc_channels:channel(), non_neg_integer())
    -> ok | {error, old_round}.
check_round_greater_than_last(Channel, Round) ->
    case aesc_channels:round(Channel) < Round of
        true  -> ok;
        false -> {error, old_round}
    end.

-spec check_is_peer(aec_keys:pubkey(), list(aec_keys:pubkey())) -> ok | {error, account_not_peer}.
check_is_peer(PubKey, Peers) ->
    case lists:member(PubKey, Peers) of
        true  -> ok;
        false -> {error, account_not_peer}
    end.

-spec check_are_funds_in_channel(aesc_channels:id(), non_neg_integer(), aec_trees:trees()) ->
                                        ok | {error, insufficient_channel_funds}.
check_are_funds_in_channel(ChannelId, Amount, Trees) ->
    ChannelsTree = aec_trees:channels(Trees),
    Channel      = aesc_state_tree:get(ChannelId, ChannelsTree),
    case aesc_channels:total_amount(Channel) >= Amount of
        true  -> ok;
        false -> {error, insufficient_channel_funds}
    end.

-spec check_state_hash_size(binary()) -> boolean().
check_state_hash_size(Hash) ->
    byte_size(Hash) =:= aec_base58c:byte_size_for_type(state).

-spec deserialize_payload(binary()) -> {ok, aetx_sign:signed_tx(), aesc_offchain_tx:tx()}
                                         | {ok, last_onchain}
                                         | {error, bad_offchain_state_type}.
deserialize_payload(<<>>) ->
    {ok, last_onchain};
deserialize_payload(Payload) ->
    try
        SignedTx = aetx_sign:deserialize_from_binary(Payload),
        Tx       = aetx_sign:tx(SignedTx),
        case aetx:specialize_type(Tx) of
            {channel_offchain_tx, PayloadTx} ->
                {ok, SignedTx, PayloadTx};
            _ ->
                {error, bad_offchain_state_type}
        end
    catch _:_ ->
            {error, payload_deserialization_failed}
    end.


%%%===================================================================
%%% Check payload for slash, solo close and snapshot
%%%===================================================================

check_solo_close_payload(ChannelId, FromPubKey, Nonce, Fee, Payload,
                         PoI, Trees) ->
    case get_vals([get_channel(ChannelId, Trees),
                   deserialize_payload(Payload)]) of
        {error, _} = E -> E;
        {ok, [Channel, last_onchain]} ->
            Checks =
                [fun() -> aetx_utils:check_account(FromPubKey, Trees, Nonce, Fee) end,
                 fun() -> check_is_active(Channel) end,
                 fun() -> check_root_hash_in_channel(Channel, PoI) end,
                 fun() -> check_peers_and_amounts_in_poi(Channel, PoI) end
                ],
            aeu_validation:run(Checks);
        {ok, [Channel, {SignedState, PayloadTx}]} ->
            ChannelId = aesc_channels:id(Channel),
            Checks =
                [ fun() -> aetx_utils:check_account(FromPubKey, Trees, Nonce,
                                                    Fee) end,
                  fun() -> check_is_active(Channel) end,
                  fun() -> check_payload(Channel, PayloadTx, FromPubKey, SignedState,
                                          Trees, solo_close) end,
                  fun() -> check_poi(Channel, PayloadTx, PoI) end
                ],
            aeu_validation:run(Checks)
    end.

check_slash_payload(ChannelId, FromPubKey, Nonce, Fee, Payload,
                    PoI, Height, Trees) ->
    case get_vals([get_channel(ChannelId, Trees),
                   deserialize_payload(Payload)]) of
        %% TODO: gas costs
        {error, _} = E -> E;
        {ok, [_Channel, last_onchain]} ->
            {error, slash_must_have_payload};
        {ok, [Channel, {SignedState, PayloadTx}]} ->
            ChannelId = aesc_channels:id(Channel),
            Checks =
                [ fun() -> aetx_utils:check_account(FromPubKey, Trees, Nonce,
                                                    Fee) end,
                  fun() -> check_is_closing(Channel, Height) end,
                  fun() -> check_payload(Channel, PayloadTx, FromPubKey, SignedState,
                                          Trees, slash) end,
                  fun() -> check_poi(Channel, PayloadTx, PoI) end
                ],
            aeu_validation:run(Checks)
    end.

check_force_progress(ChannelId, FromPubKey, Nonce, Fee,
                     Payload, SoloPayload, Addresses,
                     PoI, NewPoI, _Height, Trees) ->
    case get_vals([get_channel(ChannelId, Trees),
                   deserialize_payload(Payload),
                   deserialize_payload(SoloPayload)]) of
        {error, _} = E -> E;
        {ok, [_Channel, last_onchain, _]} ->
            %TODO: use last on-chain state
            {error, force_progrsss_must_have_payload};
        {ok, [_Channel, _, last_onchain]} ->
            {error, force_progrsss_must_have_payload};
        {ok, [Channel, {SignedState, PayloadTx},
                       {SoloSignedState, SoloPayloadTx}]} ->
            ChannelId = aesc_channels:id(Channel),
            Checks =
                [ fun() -> aetx_utils:check_account(FromPubKey, Trees, Nonce,
                                                    Fee) end,
                  fun() -> check_payload(Channel, PayloadTx, FromPubKey, SignedState,
                                          Trees, force_progress) end,
                  fun() -> check_solo_signed_payload(Channel, SoloPayloadTx,
                                                     FromPubKey, SoloSignedState,
                                          Trees, force_progress) end,
                  fun() ->
                      R0 = aesc_offchain_tx:round(PayloadTx),
                      R1 = aesc_offchain_tx:round(SoloPayloadTx),
                      case R0 =:= R1 - 1 of
                          true -> ok;
                          false -> {error, wrong_round}
                      end
                  end,
                  fun() -> validate_addresses(Addresses, PoI, Channel) end,
                  fun() -> validate_addresses(Addresses, NewPoI, Channel) end,
                  fun() -> check_root_hash_in_payload(PayloadTx, PoI) end,
                  fun() -> check_call_and_caller(SoloPayloadTx, FromPubKey,
                                                 Addresses)
                  end
                ],
            aeu_validation:run(Checks)
    end.

check_solo_snapshot_payload(ChannelId, FromPubKey, Nonce, Fee, Payload,
                            Trees) ->
    case get_vals([aesc_utils:get_channel(ChannelId, Trees),
                   aesc_utils:deserialize_payload(Payload)]) of
        {error, _} = E -> E;
        {ok, [_Channel, last_onchain]} ->
            {error, snapshot_must_have_payload};
        {ok, [Channel, {SignedState, PayloadTx}]} ->
            ChannelId = aesc_channels:id(Channel),
            Checks =
                [ fun() -> aetx_utils:check_account(FromPubKey, Trees, Nonce,
                                                    Fee) end,
                  fun() -> check_is_active(Channel) end,
                  fun() -> check_payload(Channel, PayloadTx, FromPubKey, SignedState,
                                          Trees, solo_snapshot) end
                ],
            aeu_validation:run(Checks)
    end.

check_poi(Channel, PayloadTx, PoI) ->
    Checks =
        [fun() -> check_root_hash_in_payload(PayloadTx, PoI) end,
         fun() -> check_peers_and_amounts_in_poi(Channel, PoI) end
        ],
    aeu_validation:run(Checks).

check_payload(Channel, PayloadTx, FromPubKey, SignedState, Trees, Type) ->
    ChannelId = aesc_channels:id(Channel),
    Checks =
        [fun() -> check_channel_id_in_payload(Channel, PayloadTx) end,
          fun() -> check_round_in_payload(Channel, PayloadTx) end,
          fun() -> is_peer_or_delegate(ChannelId, FromPubKey, SignedState, Trees, Type) end,
          fun() -> aetx_sign:verify(SignedState, Trees) end
        ],
    aeu_validation:run(Checks).

check_solo_signed_payload(Channel, PayloadTx, FromPubKey, SignedState, Trees, Type) ->
    ChannelId = aesc_channels:id(Channel),
    Checks =
        [fun() -> check_channel_id_in_payload(Channel, PayloadTx) end,
          fun() -> check_round_in_payload(Channel, PayloadTx) end,
          fun() -> is_peer_or_delegate(ChannelId, FromPubKey, SignedState, Trees, Type) end,
          fun() -> aetx_sign:verify_incomplete(SignedState, [FromPubKey]) end
        ],
    aeu_validation:run(Checks).

check_peers_and_amounts_in_poi(Channel, PoI) ->
    InitiatorPubKey   = aesc_channels:initiator(Channel),
    ResponderPubKey   = aesc_channels:responder(Channel),
    ChannelAmount     = aesc_channels:total_amount(Channel),
    case aesc_utils:accounts_in_poi([InitiatorPubKey, ResponderPubKey], PoI) of
        {error, _} = Err -> Err;
        {ok, [PoIInitiatorAcc, PoIResponderAcc]} ->
            PoIInitiatorAmt = aec_accounts:balance(PoIInitiatorAcc),
            PoIResponderAmt = aec_accounts:balance(PoIResponderAcc),
            PoIAmount       = PoIInitiatorAmt + PoIResponderAmt,
            case ChannelAmount =:= PoIAmount of
                true  -> ok;
                false -> {error, poi_amounts_change_channel_funds}
            end
    end.

is_peer_or_delegate(ChannelId, FromPubKey, SignedState, Trees, Type) ->
    case is_peer(FromPubKey, SignedState, Trees) of
        ok -> ok;
        {error, account_not_peer} = E0 ->
            case is_delegatable_tx_type(Type) of
                true ->
                    case is_delegate(ChannelId, FromPubKey, Trees) of
                        ok -> ok;
                        {error, account_not_delegate} ->
                            {error, account_not_peer_or_delegate};
                        {error,_} = E ->
                            E
                    end;
                false ->
                    E0
            end
    end.

is_peer(FromPubKey, SignedState, Trees) ->
    Tx = aetx_sign:tx(SignedState),
    case aetx:signers(Tx, Trees) of
        {ok, Signers} ->
            case lists:member(FromPubKey, Signers) of
                true  -> ok;
                false -> {error, account_not_peer}
            end;
        {error, _Reason}=Err -> Err
    end.

is_delegatable_tx_type(Type) ->
    lists:member(Type, delegatable_tx_types()).

delegatable_tx_types() ->
    [slash].

is_delegate(ChannelId, FromPubKey, Trees) ->
    with_channel(fun(Channel) ->
                         is_delegate_(Channel, FromPubKey)
                 end, ChannelId, Trees).

is_delegate_(Channel, FromPubKey) ->
    case lists:member(FromPubKey, aesc_channels:delegates(Channel)) of
        true ->
            ok;
        false ->
            {error, account_not_delegate}
    end.

with_channel(F, ChannelId, Trees) ->
    case get_channel(ChannelId, Trees) of
        {ok, Channel}  -> F(Channel);
        {error, _} = E -> E
    end.

check_channel_id_in_payload(Channel, PayloadTx) ->
    case aesc_channels:id(Channel) =:= aesc_offchain_tx:channel_id(PayloadTx) of
        false -> {error, bad_state_channel_id};
        true -> ok
    end.

check_round_in_payload(Channel, PayloadTx) ->
    check_round_greater_than_last(Channel, aesc_offchain_tx:round(PayloadTx)).

check_root_hash_in_payload(PayloadTx, PoI) ->
    ChannelStateHash = aesc_offchain_tx:state_hash(PayloadTx),
    PoIHash = aec_trees:poi_hash(PoI),
    case ChannelStateHash =:= PoIHash of
        true -> ok;
        false -> {error, invalid_poi_hash}
    end.

check_root_hash_in_channel(Channel, PoI) ->
    ChannelStateHash = aesc_channels:state_hash(Channel),
    PoIHash = aec_trees:poi_hash(PoI),
    case ChannelStateHash =:= PoIHash of
        true -> ok;
        false -> {error, invalid_poi_hash}
    end.

%%%===================================================================
%%% Process payload for slash and solo close
%%%===================================================================

process_solo_close(ChannelId, FromPubKey, Nonce, Fee,
                   Payload, PoI, Height, Trees) ->
    process_solo_close_slash(ChannelId, FromPubKey, Nonce, Fee,
                             Payload, PoI, Height, Trees).


process_slash(ChannelId, FromPubKey, Nonce, Fee,
              Payload, PoI, Height, Trees) ->
    process_solo_close_slash(ChannelId, FromPubKey, Nonce, Fee,
                             Payload, PoI, Height, Trees).

process_solo_snapshot(ChannelId, FromPubKey, Nonce, Fee, Payload, Trees) ->
    ChannelsTree0      = aec_trees:channels(Trees),
    Channel0 = aesc_state_tree:get(ChannelId, ChannelsTree0),
    {ok, _SignedTx, PayloadTx} = deserialize_payload(Payload),
    Channel1 = aesc_channels:snapshot_solo(Channel0, PayloadTx),
    ChannelsTree1 = aesc_state_tree:enter(Channel1, ChannelsTree0),
    Trees1 = aec_trees:set_channels(Trees, ChannelsTree1),
    AccountsTree0      = aec_trees:accounts(Trees),
    FromAccount0       = aec_accounts_trees:get(FromPubKey, AccountsTree0),
    {ok, FromAccount1} = aec_accounts:spend(FromAccount0, Fee, Nonce),
    AccountsTree1      = aec_accounts_trees:enter(FromAccount1, AccountsTree0),
    Trees2 = aec_trees:set_accounts(Trees1, AccountsTree1),
    {ok, Trees2}.

process_solo_close_slash(ChannelId, FromPubKey, Nonce, Fee,
                         Payload, PoI, Height, Trees) ->
    AccountsTree0      = aec_trees:accounts(Trees),
    ChannelsTree0      = aec_trees:channels(Trees),
    FromAccount0       = aec_accounts_trees:get(FromPubKey, AccountsTree0),
    {ok, FromAccount1} = aec_accounts:spend(FromAccount0, Fee, Nonce),
    AccountsTree1      = aec_accounts_trees:enter(FromAccount1, AccountsTree0),

    Channel0 = aesc_state_tree:get(ChannelId, ChannelsTree0),
    Channel1 =
        case aesc_utils:deserialize_payload(Payload) of
            {ok, _SignedTx, PayloadTx} ->
                aesc_channels:close_solo(Channel0, PayloadTx, PoI, Height);
            {ok, last_onchain} ->
                aesc_channels:close_solo(Channel0, PoI, Height)
        end,
    ChannelsTree1 = aesc_state_tree:enter(Channel1, ChannelsTree0),
    Trees1 = aec_trees:set_accounts(Trees, AccountsTree1),
    Trees2 = aec_trees:set_channels(Trees1, ChannelsTree1),
    {ok, Trees2}.

process_force_progress(ChannelId, _FromPubKey, _Nonce, _Fee,
                       _Payload, SoloPayload, Addresses,
                       PoI, _NewPoI, _Height, Trees) ->
    %% TODO: gas costs
    {ok, [Channel, {_SoloSignedState, SoloPayloadTx}]} =
          get_vals([get_channel(ChannelId, Trees),
                   deserialize_payload(SoloPayload)]),
    [Update] = aesc_offchain_tx:updates(SoloPayloadTx),
    %% use in gas payment
    _UpdateFrom = aesc_offchain_update:extract_caller(Update),
    _ContractPubkey = aesc_offchain_update:extract_contract_id(Update),
    %{ok, Contract} = aec_trees:lookup_poi(contracts, ContractPubkey, PoI),
    PoITrees0 = trees_from_poi(Addresses, PoI),
    %% TODO: expose gas
    Reserve = aesc_channels:channel_reserve(Channel),
    Round = aesc_offchain_tx:round(SoloPayloadTx),
    PoITrees = aesc_offchain_update:apply_on_trees(Update, PoITrees0, Round,
                                                   Reserve),
    PoITreesHash = aec_trees:hash(PoITrees),
    ExpectedHash = aesc_offchain_tx:state_hash(SoloPayloadTx),

    ChannelsTree0 = aec_trees:channels(Trees),
    Channel1 = aesc_channels:snapshot_solo(Channel, SoloPayloadTx),
    ChannelsTree1 = aesc_state_tree:enter(Channel1, ChannelsTree0),
    Trees1 = aec_trees:set_channels(Trees, ChannelsTree1),
    {ok, Trees1}.


get_vals(List) ->
    R =
        lists:foldl(
            fun(_, {error, _} = Err) -> Err;
              ({error, _} = Err, _) -> Err;
              ({ok, Val}, Accum) -> [Val | Accum];
              ({ok, Val1, Val2}, Accum) -> [{Val1, Val2} | Accum]
            end,
            [],
            List),
    case R of
        {error, _} = Err -> Err;
        L when is_list(L) -> {ok, lists:reverse(L)}
    end.

validate_addresses(Addresses, PoI, Channel) ->
    GetAccount =
        fun(AddressID) ->
            {Tag,  Pubkey} = aec_id:specialize(AddressID),
            case aec_trees:lookup_poi(accounts, Pubkey, PoI) of
                {error, _} -> {error, not_found};
                {ok, Account} -> {ok, {Tag, Account}}
            end
        end,
    case get_vals([GetAccount(ID) || ID <- Addresses]) of
        {error, not_found} = Err -> Err;
        {ok, AccountsMixed} ->
            Accounts = [Acc || {T, Acc} <- AccountsMixed, T =:= account],
            Contracts = [C || {T, C} <- AccountsMixed, T =:= contract],
            Checks = [
                fun() -> check_amounts_do_not_exceed_total_balance(Accounts,
                                                                   Contracts,
                                                                   Channel)
                end,
                fun() ->
                    ContractKeys = [aec_accounts:pubkey(Acc) || Acc <- Contracts],
                    check_contracts_in_poi(ContractKeys, PoI)
                end],
            aeu_validation:run(Checks)
    end.

check_amounts_do_not_exceed_total_balance(Accounts, Contracts, Channel) ->
    AllBalances = lists:sum(
                    [aec_accounts:balance(Acc) || Acc <- Accounts ++ Contracts]),
    case AllBalances > aesc_channels:total_amount(Channel) of
        true -> {error, poi_amounts_change_channel_funds};
        false -> ok
    end.

check_contracts_in_poi(Pubkeys, PoI) ->
    AllPresent =
        lists:all(
            fun(Pubkey) ->
                case aec_trees:lookup_poi(contracts, Pubkey, PoI) of
                    {ok, _} -> true;
                    {error, _} -> false
                end
            end,
            Pubkeys),
    case AllPresent of
        true -> ok;
        false -> {error, contract_missing_in_poi}
    end.

check_call_and_caller(SoloSignedState, FromPubKey, Addresses) ->
    case aesc_offchain_tx:updates(SoloSignedState) of
        [Update] ->
            case aesc_offchain_update:is_call(Update) of
                true ->
                    UpdateFrom = aesc_offchain_update:extract_caller(Update),
                    ContractPubkey = aesc_offchain_update:extract_contract_id(Update),
                    ContractId = aec_id:create(contract, ContractPubkey),
                    ContractProvided = lists:member(ContractId, Addresses),
                    case {UpdateFrom, ContractProvided} of
                        {FromPubKey, true} -> %% same as poster
                            ok;
                        {_, true} -> %% some other caller?
                            {error, not_caller};
                        {_, false} ->
                            {error, contract_missing}
                    end;
                false ->
                    {error, update_not_call}
            end;
        [] ->
            {error, no_update};
        _ ->
            {error, more_than_one_update}
    end.

-spec trees_from_poi([aec_id:id()], aec_trees:poi()) -> aec_trees:trees().
trees_from_poi(IDs, PoI) ->
    AddAccount =
        fun(Pubkey, Type, Trees) when Type =:= accounts
                               orelse Type =:= contracts ->
            {ok, Acc} = aec_trees:lookup_poi(accounts, Pubkey, PoI),
            Accounts0 = aec_trees:accounts(Trees),
            Accounts1 = aec_accounts_trees:enter(Acc, Accounts0),
            aec_trees:set_accounts(Trees, Accounts1)
        end,
    AddContract =
        fun(ContractPubkey, Trees) ->
            {ok, Contract} = aec_trees:lookup_poi(contracts, ContractPubkey, PoI),
            Contracts0 = aec_trees:contracts(Trees),
            Contracts1 = aect_state_tree:insert_contract(Contract, Contracts0),
            aec_trees:set_contracts(Trees, Contracts1)
        end,
    lists:foldl(
        fun(ID, AccumTrees0) ->
            {Type, Pubkey} = aec_id:specialize(ID),
            case Type of
                account ->
                    AddAccount(Pubkey, accounts, AccumTrees0);
                contract ->
                    AccumTrees = AddAccount(Pubkey, contracts, AccumTrees0),
                    AddContract(Pubkey, AccumTrees)
            end
        end,
        aec_trees:new_without_backend(),
        IDs).

%-spec trees_update_poi([aec_id:id()], aec_trees:poi()) -> aec_trees:trees().
