-module(miner_tee_worker).
-behavior(gen_server).

-export([sign/1,
         ecdh/1,
         get_pid/0]).

-export([start_link/0,
         init/1,
         handle_call/3,
         handle_cast/2,
         terminate/2]).

-record(state, {tee_handle :: pid()}).

-spec sign(binary()) -> {ok, Signature::binary()} | {error, term()}.
sign(Binary) ->
    gen_server:call(?MODULE, {sign, Binary}).

-spec ecdh(libp2p_crypto:pubkey()) -> {ok, Preseed::binary()} | {error, term()}.
ecdh({ecc_compact, PubKey}) ->
    gen_server:call(?MODULE, {ecdh, PubKey}).

get_pid() ->
    gen_server:call(?MODULE, get_pid).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).


init([]) ->
    {ok, TZHandle} = helium_optee:start_link(),
    {ok, #state{tee_handle=TZHandle}}.


handle_call({sign, Binary}, _From, State=#state{tee_handle=Pid}) ->
    Reply = helium_optee:ecdsa_sign(Pid, crypto:hash(sha256, Binary)),
    {reply, Reply, State};
handle_call({ecdh, PubKey}, _From, State=#state{tee_handle=Pid}) ->
    Reply = helium_optee:ecdh(Pid, PubKey),
    {reply, Reply, State};
handle_call(get_pid, _From, State=#state{tee_handle=Pid}) ->
    {reply, {ok, Pid}, State};
handle_call(_Msg, _From, State) ->
    lager:warning("unhandled call ~p", [_Msg]),
    {reply, ok, State}.


handle_cast(_Msg, State) ->
    lager:warning("unhandled cast ~p", [_Msg]),
    {noreply, State}.

terminate(_Reason, State=#state{}) ->
    catch helium_optee:stop(State#state.tee_handle).
