:- style_check(-singleton).

problems(Path) :- find_intra_procedural_problems_first(Path), !. % 🛑 STOP if this worked !
problems(Path) :- then_look_for_inter_procedural_prblems(Path).

%find_intra_procedural_problems_first(Path) :- owasp_top_10_intra(Path).
%find_intra_procedural_problems_first(Path) :- arbitrary_file_write_intra(Path).
%find_intra_procedural_problems_first(Path) :- unsafe_deserialization_intra(Path).
%find_intra_procedural_problems_first(Path) :- arbitrary_file_deletion_intra(Path).
find_intra_procedural_problems_first(Path) :- open_redirect_intra(Path).
find_intra_procedural_problems_first(Path) :- arbitrary_file_read_intra(Path).
% add more kinds here ...

owasp_top_10_intra(Path) :- injection_intra(Path).
owasp_top_10_intra(Path) :- ssrf_intra(Path).
% add more kinds here ...

injection_intra(Path) :- rce_intra(Path).
injection_intra(Path) :- sqli_intra(Path).
% add more kinds here ...

rce_intra(Path) :-
    utils_user_input(UserInput),
    utils_cmd_exec(Call),
    utils_intra_dataflow_path(UserInput, Call, Path).

sqli_intra(Path) :-
    utils_user_input(UserInput),
    utils_sqli(Call),
    utils_intra_dataflow_path(UserInput, Call, Path).

ssrf_intra(Path) :-
    utils_user_input(UserInput),
    utils_ssrf(Call),
    utils_intra_dataflow_path(UserInput, Call, Path).

arbitrary_file_read_intra(Path) :-
    utils_user_input(UserInput),
    utils_arbitrary_file_read(Call),
    utils_intra_dataflow_path(UserInput, Call, Path).

unsafe_deserialization_intra(Path) :-
    utils_user_input(UserInput),
    unsafe_deserialization(Call),
    utils_intra_dataflow_path(UserInput, Call, Path).

arbitrary_file_deletion_intra(Path) :-
    utils_user_input(UserInput),
    utils_arbitrary_file_deletion(Call),
    utils_intra_dataflow_path(UserInput, Call, Path).

open_redirect_intra(Path) :-
    utils_user_input(UserInput),
    utils_open_redirect(Call),
    utils_intra_dataflow_path(UserInput, Call, Path).

utils_cmd_exec(Call) :- utils_cmd_exec_go(Call).
% add more kinds here ...

utils_cmd_exec_go(Call) :- kb_call_resolved(Call, 'os/exec.CommandContext').
utils_cmd_exec_go(Call) :- kb_call_resolved(Call, 'os/exec.Command').
% add more kinds here ...

utils_sqli(Call) :- utils_sqli_php(Call).
% add more kinds here ...

utils_sqli_php(Call) :- kb_call_resolved(Call, 'Yii.app.db.createCommand.queryAll').
% add more kinds here ...

utils_ssrf(Call) :- kb_call_resolved(Call, 'requests.post').
% add more kinds here ...

utils_http_get_handler_request_object( GetHandler,  RequestObject, Url) :- utils_http_get_handler_request_object_nextjs( GetHandler,  RequestObject, Url).
utils_http_post_handler_request_object(PostHandler, RequestObject, Url) :- utils_http_post_handler_request_object_nextjs(PostHandler, RequestObject, Url).
% add more kinds here ...

endswith(StringInput, StringSuffix) :- atom_concat(_, StringSuffix, StringInput).

utils_http_get_handler_request_object_nextjs(GetHandler, RequestObject, Url) :-
    kb_func_def(GetHandler, 'GET', FileName, Url),
    kb_param_i_of_callable(RequestObject, _, GetHandler),
    kb_param_has_name(RequestObject, 'req'),
    kb_param_has_resolved_type(RequestObject, 'next/server.NextRequest'),
    endswith(FileName, 'route.ts').

utils_http_post_handler_request_object_nextjs(PostHandler, RequestObject, Url) :-
    kb_func_def(PostHandler, 'POST', FileName, Url),
    kb_param_i_of_callable(RequestObject, _, PostHandler),
    kb_param_has_name(RequestObject, 'req'),
    kb_param_has_resolved_type(RequestObject, 'next/server.NextRequest'),
    endswith(FileName, 'route.ts').

utils_authenticated_http_post_handler_request_object(PostHandler, RequestObject, Url) :-
    utils_http_post_handler_request_object(PostHandler, RequestObject, Url),
    kb_called_from(AuthCall, PostHandler),
    utils_authenticating_function(AuthCall).
% add more requirements here ...

utils_authenticating_function(Call) :- kb_call_1st_party_func_defined_in_file(Call, 'authenticateRequest', _).
utils_authenticating_function(Call) :- kb_call_1st_party_func_defined_in_dir(Call, 'authenticateRequest', _).
% add more authenticator names here (tier-1 catalog) ...

% bounded "early-return authenticating function" recognition — no transitive
% closure by design. two levels only:
%   level-0: base name catalog below (asserted by name; structural verification
%            via an early-return-on-param KB fact is a future step)
%   level-1: a callable that calls a level-0 authenticator ( single hop )

utils_early_return_authenticating_function_name('authenticateRequest').
% add more authenticator names here ...

utils_early_return_authenticating_function(Callable) :-
    kb_func_def(Callable, Name, _, _),
    utils_early_return_authenticating_function_name(Name).

utils_early_return_authenticating_function(Callable) :-
    kb_called_from(Call, Callable),
    utils_call_to_level_0_authenticator(Call).

utils_call_to_level_0_authenticator(Call) :-
    kb_call_1st_party_func_defined_in_file(Call, Name, _),
    utils_early_return_authenticating_function_name(Name).

utils_call_to_level_0_authenticator(Call) :-
    kb_call_1st_party_func_defined_in_dir(Call, Name, _),
    utils_early_return_authenticating_function_name(Name).

% -----------------------------------------------------------------------------
% utils_early_return_null_on_missing_request_header_value( Callable, KeyName )
%
% Recognises the strict-tier "early return null on missing request-header
% value" idiom. Concretely, inside `Callable` :
%
%     const V = request.headers.get( 'X-Api-Key' );
%     if ( !V ) return null;
%
% Composed from four ingredients :
%
%   1. `kb_called_from` + `kb_call_resolved`  : a call to
%      `nodejs.Request.headers.get` occurs inside Callable.
%
%   2. `kb_arg_i_for_call` + `kb_const_string`: the header key name is a
%      compile-time string ( bound to `KeyName` for downstream ranking ).
%
%   3. `kb_gated_return_null`                  : an early-return guard
%      whose returned value is a null literal ( derived on top of the
%      more general `kb_gated_return( Cond, ReturnedValue )` fact ).
%
%   4. `utils_intra_dataflow_path`             : intra-procedural
%      dataflow ties `headers.get( KeyName )` -> gate condition value.
%
% This is the *strict tier* of the "authenticating function" first gate.
% The nodejs/nextjs surface receiver is hardcoded here; sibling clauses
% for other frameworks / receivers can be added as leaf additions -- no
% existing clause needs to change.

utils_early_return_null_on_missing_request_header_value( Callable, KeyName ) :-
    kb_called_from( Call, Callable ),
    kb_call_resolved( Call, 'nodejs.Request.headers.get' ),
    kb_arg_i_for_call( KeyArg, 0, Call ),
    kb_const_string( KeyArg, KeyName ),
    kb_gated_return_null( Cond ),
    utils_intra_dataflow_path( Call, Cond, _ ).

% kb_gated_return_null( Cond ) : an early-return guard whose returned
% value is a language-level absence literal ( `null`, `None`, `nil` --
% all normalised to the same `kb_const_null` fact by kbgen ). Layered on
% top of the more general `kb_gated_return` fact so that sibling
% derivations ( e.g. `kb_gated_return_false`, `kb_gated_throw`, ... )
% can be added later as pure leaf additions.

kb_gated_return_null( Cond ) :-
    kb_gated_return( Cond, ReturnedValue ),
    kb_const_null( ReturnedValue ).

% -----------------------------------------------------------------------------
% utils_function_returns_bad_http_response( Function )
%
% Recognizes callables that emit an *error* http response ( 401 / 403 / 404
% / 500 / ... ). Together with the db-lookup polarity primitive, this is
% the second building block of the "happy-path authenticator polarity"
% compass discussed in the OWASP notes.
%
% Layered so that new languages / frameworks / codes are all leaf-additions
% -- no existing clause needs to change to extend it :
%
%     utils_function_returns_bad_http_response( Function ).
%     |
%     +-- utils_function_returns_bad_http_response_ts( Function ).      % TypeScript ( nodejs.Response.json )
%     |   |
%     |   +-- utils_function_returns_bad_http_response_ts_401( F ).
%     |   +-- utils_function_returns_bad_http_response_ts_403( F ).
%     |   +-- utils_function_returns_bad_http_response_ts_404( F ).
%     |   ... add more "bad" codes here ( 400, 405, 409, 422, 429, 500, ... ) ...
%     |
%     ... add more kinds here ( _python, _go, _php, ... ) ...
%
% Structural pattern for TypeScript / nodejs :
%
%     Response.json( <body>, { status: <bad-code> } )
%
% After ts-parser-actions instrumentation this becomes the ast call tree
%
%     Response.json( <body>, dictify( kv( "status", <bad-code> ) ) )
%
% ( see `TsParser.y::exp_dict` -- object literals lower to a call whose
%  callee is the bare name `dictify` ; and `TsParserActions.hs::property`
%  lowers each `k: v` pair to a call whose callee is the instrumented
%  bare name `<dhscanner-instrumentation>[kv]` with args `[ k, v ]` --
%  casing is exact ).
%
% Known kbgen gap ( scaffolded here, activated by a follow-up version bump ) :
%
%     kb_const_int( Loc, Value )
%
% is not emitted today ( only kb_const_string / kb_const_bool_true exist
% -- see `Kbgen.hs::prologify_*` ). Every leaf below already carries its
% code as data, so adding kb_const_int to kbgen is a *pure activation* :
% no edit needed here to start discriminating 401 from 403 from 404.

utils_function_returns_bad_http_response(Function) :-
    utils_function_returns_bad_http_response_ts(Function).
% add more languages / frameworks here ...

utils_function_returns_bad_http_response_ts(Function) :-
    utils_function_returns_bad_http_response_ts_401(Function).
utils_function_returns_bad_http_response_ts(Function) :-
    utils_function_returns_bad_http_response_ts_403(Function).
utils_function_returns_bad_http_response_ts(Function) :-
    utils_function_returns_bad_http_response_ts_404(Function).
% add more "bad" codes here ...

utils_function_returns_bad_http_response_ts_401(Function) :-
    utils_ts_response_json_with_status(Function, 401).
utils_function_returns_bad_http_response_ts_403(Function) :-
    utils_ts_response_json_with_status(Function, 403).
utils_function_returns_bad_http_response_ts_404(Function) :-
    utils_ts_response_json_with_status(Function, 404).

% Structural walk from the outer `nodejs.Response.json` call down through
% the `dictify( kv( "status", Code ) )` instrumented dict.
%
% NOTE: `kb_arg_i_for_call( Arg, Index, Call )` is emitted by kbgen with
% Call = Bitcode.callLocation and Arg = Bitcode.locationValue of each arg
% value ( see `Factify.hs::getArgiForCallFacts` ). For the recursive
% descent into `DictifyCallLoc` and `KvCallLoc` below to unify, those two
% locations must coincide on call-valued args -- true in SSA-style
% bitcode, but verify against a real KB the first time this predicate
% is exercised end-to-end.
utils_ts_response_json_with_status(Function, Code) :-
    kb_call_resolved(OuterCall, 'nodejs.Response.json'),
    kb_arg_i_for_call(DictifyCallLoc, 1, OuterCall),
    kb_arg_i_for_call(KvCallLoc, _, DictifyCallLoc),
    kb_arg_i_for_call(KeyLoc, 0, KvCallLoc),
    kb_const_string(KeyLoc, 'status'),
    kb_arg_i_for_call(ValueLoc, 1, KvCallLoc),
    kb_const_int(ValueLoc, Code),
    kb_called_from(OuterCall, Function).

utils_arbitrary_file_read(Call) :- utils_arbitrary_file_read_nodejs(Call).
utils_arbitrary_file_read(Call) :- utils_arbitrary_file_read_nodejs_sendFile(Call).
% add more kinds here ...

utils_arbitrary_file_read_nodejs_sendFile(Call) :-
    kb_call_resolved(GetRequestHandler, 'express.Router.route.get'),
    kb_call_method_of_untyped_named_param( Call, 'sendFile', Param ),
    kb_param_has_name( Param, 'res' ),
    kb_arg_i_for_call( Lambda, 0, GetRequestHandler ),
    kb_param_i_of_callable( Param, 1, Lambda ).

utils_arbitrary_file_read_nodejs(Call) :-
    kb_call_resolved(Call, 'fs/promises.readFile').

utils_arbitrary_file_deletion(Call) :- utils_arbitrary_file_deletion_go(Call).

utils_arbitrary_file_deletion_go(Call) :-
    kb_call_resolved(Call, 'os.Remove').

unsafe_deserialization(Call) :- unsafe_deserialization_ruby(Call).
% add more kinds here ...

unsafe_deserialization_ruby(Call) :-
    kb_call_resolved(Call, 'YAML.load_stream').

utils_open_redirect(Call) :- utils_open_redirect_python(Call).
% add more kinds here ...

utils_open_redirect_python(Call) :-
    kb_class_has_3rd_party_super(Class, _, 'tornado.web.RequestHandler'),
    kb_call_method_of_class(Call, 'redirect', Class).

utils_open_redirect_python(Call) :-
    kb_class_has_3rd_party_super(Class, _, 'tornado.web.RequestHandler'),
    kb_call_method_of_class(Call, 'redirect', Subclass),
    kb_class_has_1st_party_super(Subclass, Name, DefinedInFile),
    kb_class_def(Class, Name, DefinedInFile).

% add more kinds here ...

then_look_for_inter_procedural_prblems(Path) :- owasp_top_10(Path).
% add more kinds here ...

owasp_top_10(Path) :- ssrf(Path).
owasp_top_10(Path) :- arbitrary_file_write(Path).
% add more kinds here ...

injection(Path) :- rce(Path).
injection(Path) :- sqli(Path).
% add more kinds here ...

ssrf(Path) :-
    utils_http_request(Call),
    utils_user_input(UserInput),
    utils_dataflow_path(UserInput, Call, Path).

arbitrary_file_write(Path) :-
    utils_user_input(UserInput),
    utils_arbitrary_file_write(Arg),
    utils_dataflow_path(UserInput, Arg, Path).

utils_http_request(Call) :- utils_http_request_go(Call).
% add more kinds here ...

utils_arbitrary_file_write(Arg) :- utils_arbitrary_file_write_nodejs(Arg).
% add more kinds here ...

utils_arbitrary_file_write_nodejs(Arg) :-
    kb_call_resolved(Call, 'fs/promises.writeFile'),
    kb_arg_i_for_call(Arg, 0, Call).

utils_http_request_go(Call) :-
    kb_call_resolved(Call, 'net/http.Get').

rce(Path) :-
    utils_user_input(UserInput),
    utils_dataflow_path(UserInput, Call, Path).

utils_has_prepared_statement_fqn(PreparedStatement) :-
    kb_has_fqn(PreparedStatement, 'gorm.io/gorm/clause.OrderByColumn').
    % add more kinds here ...

sqli(Path) :- sqli_php(Path).
% add more kinds here ...

sqli_php(Path) :- sqli_php_yii(Path).
% add more kinds here ...

sqli_php_yii(Path) :-
    kb_call_resolved(Call, 'Yii.app.db.createCommand.queryAll'),
    utils_user_input(UserInput),
    utils_dataflow_path(UserInput, Call, Path).

user_input_might_be_assigned_to(Fqn, Path) :-
    kb_has_fqn(Target, Fqn),
    utils_user_input(UserInput),
    utils_dataflow_path(UserInput, Target, Path).

user_input_might_reach_function(Fqn, Path) :-
    kb_call_resolved(Call, Fqn),
    utils_user_input(UserInput),
    utils_dataflow_path(UserInput, Call, Path).

utils_user_input(UserInput) :- utils_user_input_originated_from_pip_tornado_get_query_argument(UserInput).
utils_user_input(UserInput) :- utils_user_input_originated_from_npm_express_request_handler(UserInput).
utils_user_input(UserInput) :- utils_user_input_originated_from_golang_echo_get_query_param(UserInput).
utils_user_input(UserInput) :- utils_user_input_originated_from_ts_next_request(UserInput).
% add more web frameworks here ...

utils_user_input_originated_from_ts_next_request(Param) :-
    kb_param_has_name(Param, 'req'),
    kb_param_has_resolved_type(Param, 'next/server.NextRequest').

utils_user_input_originated_from_pip_tornado_get_query_argument(Call) :-
    kb_call_method_of_class(Call, 'get_query_argument', Subclass),
    kb_class_has_3rd_party_super(Subclass, _, 'tornado.web.RequestHandler').

utils_user_input_originated_from_pip_tornado_get_query_argument(Call) :-
    kb_call_method_of_class(Call, 'get_query_argument', Subclass),
    kb_class_has_3rd_party_super(Class, _, 'tornado.web.RequestHandler'),
    kb_class_has_1st_party_super(Subclass, ClassName, DefinedInFile),
    kb_class_def(Class, ClassName, DefinedInFile).

utils_user_input_originated_from_npm_express_request_handler(Param) :-
    kb_call_resolved(GetRequestHandler, 'express.Router.route.get'),
    kb_param_has_name(Param, 'req'),
    kb_param_i_of_callable(Param, 0, Lambda),
    kb_arg_i_for_call(Lambda, 0, GetRequestHandler).

utils_user_input_originated_from_golang_echo_get_query_param(QueryParam) :-
    kb_call_resolved(Call, 'echo.Group.GET'),
    kb_param_has_resolved_type(Param, 'echo.Context'),
    kb_call_resolved(QueryParam, 'echo.Context.QueryParam'),
    kb_arg_i_for_call(Url, 0, Call),
    kb_const_string(Url, _),
    kb_arg_i_for_call(Lambda, 1, Call),
    kb_param_i_of_callable(Param, 0, Lambda),
    utils_intra_dataflow_path(Param, QueryParam, _).

utils_intra_dataflow_path(U,V,Path) :-
    between(1,10,N),
    utils_bounded_intra_dataflow_path(U,V,N,[U],Path),
    !.

utils_bounded_intra_dataflow_path(A,C,N,_,[(A, C)]) :-
    N >= 1,
    kb_dataflow_edge(A,C).

utils_bounded_intra_dataflow_path(A,C,N,Visited,[(A,B)|Path]) :-
    N >= 2,
    kb_dataflow_edge(A,B),
    \+ member(B,Visited),
    N_MINUS_1 is N - 1,
    utils_bounded_intra_dataflow_path(B,C,N_MINUS_1,[B|Visited],Path).

utils_dataflow_path(U,V,Path) :-
    utils_interprocedural_dataflow_edge(Call,Callee),
    between(1,10,CallerSideDataflowPathLen),
    between(1,10,CalleeSideDataflowPathLen),
    utils_bounded_intra_dataflow_path(U,Call,CallerSideDataflowPathLen,[U],CallerSidePath),
    utils_bounded_intra_dataflow_path(Callee,V,CalleeSideDataflowPathLen,[U,Call,Callee],CalleeSidePath),
    \+ member(Callee,[U,Call]),
    append(CallerSidePath,[(Call,Callee)|CalleeSidePath],Path).

utils_interprocedural_dataflow_edge(U,V) :- utils_interprocedural_dataflow_edge_from_arg_to_param(U, V).

utils_interprocedural_dataflow_edge_from_arg_to_param(Arg, Param) :-
    kb_call_1st_party_func_defined_in_dir(Call, FuncName, FuncDefinedInDir),
    kb_func_def(Func, FuncName, _, FuncDefinedInDir),
    kb_arg_i_for_call(Arg, Index, Call),
    kb_param_i_of_callable(Param, Index, Func).

utils_interprocedural_dataflow_edge_from_arg_to_param(Arg, Param) :-
    kb_call_1st_party_func_defined_in_file(Call, FuncName, FuncDefinedInFile),
    kb_func_def(Func, FuncName, FuncDefinedInFile, _),
    kb_arg_i_for_call(Arg, Index, Call),
    kb_param_i_of_callable(Param, Index, Func).
