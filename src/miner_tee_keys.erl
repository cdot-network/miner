-module(miner_tee_keys).

-export([keys/0]).

keys() ->
    {ok, ECCPid} = case whereis(miner_tee_worker) of
                       undefined ->
                           %% Create a temporary ecc link to get the public key and
                           %% onboarding keys for the given slots as well as the
                           helium_optee:start_link();
                       _ECCWorker ->
                           %% use the existing ECC pid
                           miner_tee_worker:get_pid()
                   end,
    {ok, PubKey} = helium_optee:get_public_key(public_key),
    {ok, OnboardingKey} =
        case helium_optee:get_public_key(onboarding_key) of
            {ok, Key} ->
                {ok, Key};
            {error, empty_slot} ->
                %% Key not present, this slot is (assumed to be) empty so use the public key
                %% as the onboarding key
                {ok, PubKey};
            {error, not_implemented} ->
                %% onboarding_key is not implemented
                {ok, PubKey};
            Other -> Other
        end,
    case whereis(miner_tee_worker) of
        undefined ->
            %% Stop ephemeral ecc pid
            helium_optee:stop(ECCPid);
        _ ->
            ok
    end,

    #{ pubkey => PubKey,
       %% The signing and ecdh functions will use an actual
       %% worker against a named process.
       ecdh_fun => fun(PublicKey) ->
                           {ok, Bin} = miner_tee_worker:ecdh(PublicKey),
                           Bin
                   end,
       sig_fun => fun(Bin) ->
                          {ok, Sig} = miner_tee_worker:sign(Bin),
                          Sig
                  end,
       onboarding_key => libp2p_crypto:pubkey_to_b58(OnboardingKey)
     }.

