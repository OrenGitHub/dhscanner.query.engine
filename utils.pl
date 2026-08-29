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

% AuthenticatedHttpPostHandlerRequestObject query — /5 form.
%
% Same shape as `utils_http_post_handler_request_object/3`, extended with
% the two pieces of metadata that identify /how/ the handler is
% authenticated :
%
%   AuthFuncName : the name of the callable that gates PostHandler
%                  ( bound from the tier-1 authenticator name catalog
%                  via `utils_authenticating_function/3` ).
%
%   HeaderKey    : the string constant passed to `Request.headers.get(...)`
%                  inside AuthFunc — bound by the composed structural
%                  predicate `utils_early_return_null_on_missing_request_header_value/2`.
%
% Composition rationale : the catalog side (name) and the structural side
% (early-return-null on missing header) are already independently shipped
% in this file ; this predicate is where they finally get joined so both
% pieces of evidence surface in a single kbapi finding.
utils_authenticated_http_post_handler_request_object(PostHandler, RequestObject, Url, AuthFuncName, HeaderKey) :-
    utils_http_post_handler_request_object(PostHandler, RequestObject, Url),
    kb_called_from(AuthCall, PostHandler),
    utils_authenticating_function(AuthCall, AuthFuncName, AuthFunc),
    utils_early_return_null_on_missing_request_header_value(AuthFunc, HeaderKey).
% add more requirements here ...

% /3 form — binds Name and the resolved 1st-party function definition
% (Func) so callers can chain further structural checks against
% AuthFunc's body ( e.g. `utils_early_return_null_on_missing_request_header_value` ).
utils_authenticating_function(Call, Name, Func) :-
    kb_call_1st_party_func_defined_in_file(Call, Name, DefFile),
    utils_authenticating_function_name(Name),
    kb_func_def(Func, Name, DefFile, _).

utils_authenticating_function(Call, Name, Func) :-
    kb_call_1st_party_func_defined_in_dir(Call, Name, DefDir),
    utils_authenticating_function_name(Name),
    kb_func_def(Func, Name, _, DefDir).

% Structural /3 clauses -- same shape as the two clauses above but with the
% name-catalog gate ( `utils_authenticating_function_name/1` ) replaced by
% the return-values shape gate ( `utils_authenticating_function_by_return_values/1`
% defined further down ). Name is still bound from the call-resolution
% fact so downstream callers ( kbapi ) get a human-readable label alongside
% the structural evidence -- but Name is no longer required to appear in
% the tier-1 catalog. Rationale : the shape gate IS the evidence.

utils_authenticating_function(Call, Name, Func) :-
    kb_call_1st_party_func_defined_in_file(Call, Name, DefFile),
    kb_func_def(Func, Name, DefFile, _),
    utils_authenticating_function_by_return_values(Func).

utils_authenticating_function(Call, Name, Func) :-
    kb_call_1st_party_func_defined_in_dir(Call, Name, DefDir),
    kb_func_def(Func, Name, _, DefDir),
    utils_authenticating_function_by_return_values(Func).

% /1 form — retained as a thin projection over the /3 form so any
% legacy caller that only cared about "is this a call to an authenticator ?"
% keeps working.
utils_authenticating_function(Call) :- utils_authenticating_function(Call, _, _).

utils_authenticating_function_name('authenticateRequest').
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

% -----------------------------------------------------------------------------
% utils_return_value_is_bad_http_response( ReturnedValue )
%
% Return-value-anchored refinement of `utils_function_returns_bad_http_response/1`.
% The per-function version above answers "does Function contain, anywhere in
% its body, at least one bad-http response ?". This per-return version asks
% the stricter question "is THIS specific return statement's returned value
% a bad-http response ?" -- anchored on a ReturnedValue location bound by
% `kb_callable_returns_value/2` ( emitted by kbgen for every explicit return
% in a callable, plus one parser-injected fall-through at the callable's
% header location -- see `TsParserActions.hs::ensureCallableBodyEndsWithReturn` ).
%
% Same layering as the per-function form so new languages / codes remain
% pure leaf additions :
%
%     utils_return_value_is_bad_http_response( ReturnedValue ).
%     |
%     +-- utils_return_value_is_bad_http_response_ts( ReturnedValue ).
%     |   |
%     |   +-- ..._ts_401( ReturnedValue ).
%     |   +-- ..._ts_403( ReturnedValue ).
%     |   +-- ..._ts_404( ReturnedValue ).
%     |   ... add more "bad" codes here ...
%     |
%     ... add more languages / frameworks here ...

utils_return_value_is_bad_http_response(ReturnedValue) :-
    utils_return_value_is_bad_http_response_ts(ReturnedValue).
% add more languages / frameworks here ...

utils_return_value_is_bad_http_response_ts(ReturnedValue) :-
    utils_return_value_is_bad_http_response_ts_401(ReturnedValue).
utils_return_value_is_bad_http_response_ts(ReturnedValue) :-
    utils_return_value_is_bad_http_response_ts_403(ReturnedValue).
utils_return_value_is_bad_http_response_ts(ReturnedValue) :-
    utils_return_value_is_bad_http_response_ts_404(ReturnedValue).
% add more "bad" codes here ...

% 1-hop wrapper case : the returned value is a call to a 1st-party helper
% whose body itself contains a bad-http response call. Real-world guards
% rarely inline `Response.json( ... )` directly at each `return` site --
% they call a named helper like `responses.notAuthenticatedResponse()` or
% `responses.unauthorizedResponse()` which wraps the actual Response.json
% one hop deeper. This clause is what makes the shape recogniser fire on
% those guards without requiring the helpers to be inlined.
utils_return_value_is_bad_http_response_ts(ReturnedValue) :-
    utils_return_value_is_bad_http_response_via_1st_party_wrapper(ReturnedValue).

utils_return_value_is_bad_http_response_ts_401(ReturnedValue) :-
    utils_ts_response_json_at_with_status(ReturnedValue, 401).
utils_return_value_is_bad_http_response_ts_403(ReturnedValue) :-
    utils_ts_response_json_at_with_status(ReturnedValue, 403).
utils_return_value_is_bad_http_response_ts_404(ReturnedValue) :-
    utils_ts_response_json_at_with_status(ReturnedValue, 404).

% Method-call-on-imported-object case ( eg
% `responses.notAuthenticatedResponse()` ) : kbgen resolves such calls
% through `kb_call_resolved` with a Haskell-Show-formatted qualifier
% atom of the form
%
%    'FirstPartyImport (FirstPartyImportContent {firstPartyImportedLocation = "<File>", firstPartyImportedName = Just "<Qual>"}).<Method>'
%
% `utils_1st_party_wrapper_helper/2` splits that atom on `"` to recover
% the wrapper's defining file + method name and binds Helper via
% `kb_func_def/4`. From there we recurse the LEAF bad-http checkers
% ( `_ts_401` / `_ts_403` / `_ts_404` ) on the wrapper's own returns
% ( `kb_callable_returns_value/2` -- emitted for every explicit return
% plus the parser-injected fall-through, see
% `TsParserActions.hs::ensureCallableBodyEndsWithReturn` ).
%
% Bypassing `kb_call_1st_party_func_defined_in_file/3` here is
% deliberate. That fact is only emitted for BARE function calls (
% `hasPermission(...)` etc. ), not for method calls on imported objects
% -- which is exactly the shape every real-world response-helper
% follows in the formbricks codebase ( and, empirically, in every
% other nextjs app we've looked at ).
%
% Calling `_ts_401` / `_ts_403` / `_ts_404` directly ( rather than the
% dispatcher `utils_return_value_is_bad_http_response_ts/1` ) caps
% recursion at exactly one wrapper hop. A future multi-hop version
% ( eg a wrapper that itself wraps another wrapper ) can leaf-add a
% dedicated `_via_1st_party_wrapper_wrapper` clause without touching
% the leaves.
utils_return_value_is_bad_http_response_via_1st_party_wrapper(ReturnedValue) :-
    utils_1st_party_wrapper_helper(ReturnedValue, Helper),
    kb_callable_returns_value(Helper, HelperReturn),
    utils_return_value_is_bad_http_response_ts_401(HelperReturn).
utils_return_value_is_bad_http_response_via_1st_party_wrapper(ReturnedValue) :-
    utils_1st_party_wrapper_helper(ReturnedValue, Helper),
    kb_callable_returns_value(Helper, HelperReturn),
    utils_return_value_is_bad_http_response_ts_403(HelperReturn).
utils_return_value_is_bad_http_response_via_1st_party_wrapper(ReturnedValue) :-
    utils_1st_party_wrapper_helper(ReturnedValue, Helper),
    kb_callable_returns_value(Helper, HelperReturn),
    utils_return_value_is_bad_http_response_ts_404(HelperReturn).

% Extract the wrapper's ( DefFile, Method ) from a `kb_call_resolved`
% whose resolved-name atom follows the FirstPartyImport Haskell-Show
% format documented above. Splits on `"` and re-checks structural
% anchors so non-FirstPartyImport shapes ( `os/exec.Command`,
% `nodejs.Response.json`, `Yii.app.db.createCommand.queryAll`, etc. )
% cleanly FAIL rather than return garbage extractions :
%
%   Chunk[0] -- unused ; the fixed prefix
%              `FirstPartyImport (... firstPartyImportedLocation = `.
%   Chunk[1] -- the file path, bound to `File`.
%   Chunk[2..3] -- unused ; the qualifier name between the quotes.
%   Chunk[4] -- starts with `}).` followed by the method name ;
%              stripping the sentinel binds `Method`.
%
% The 5-part unification is the actual reject-non-matching-shapes gate
% -- atoms without four `"` characters ( eg `os/exec.Command` )
% produce a 1-element split_string result and fail here immediately.
utils_1st_party_wrapper_helper(ReturnedValue, Helper) :-
    kb_call_resolved(ReturnedValue, ResolvedName),
    atom_string(ResolvedName, S),
    split_string(S, "\"", "", [_, FileStr, _, _, TailStr]),
    string_concat("}).", MethodStr, TailStr),
    atom_string(File, FileStr),
    atom_string(Method, MethodStr),
    kb_func_def(Helper, Method, File, _).

% Same structural walk as `utils_ts_response_json_with_status/2` above,
% but anchored on the outer call location ( which coincides with the
% return value's location when the return is `return Response.json( ... )` )
% rather than on the enclosing callable. The per-function form composes
% trivially on top of this predicate :
%
%     utils_ts_response_json_with_status( Function, Code ) :-
%         utils_ts_response_json_at_with_status( OuterCall, Code ),
%         kb_called_from( OuterCall, Function ).
%
% Existing per-function walker is kept inline to keep this diff narrow ;
% a follow-up can refactor it to route through this predicate.
%
% Note on the missing `kb_const_string(KeyLoc, 'status')` gate :
% -----------------------------------------------------------
% The per-function walker `utils_ts_response_json_with_status/2` above
% has an extra step that binds `KeyLoc = kb_arg_i_for_call(_, 0, kv)` and
% asserts `kb_const_string(KeyLoc, 'status')` -- to filter out kv-pairs
% whose key isn't literally `status`. We deliberately omit that gate
% here because TS/JS object-literal keys written in identifier form
% ( `{ status: 401, headers }` ) are NOT emitted as `kb_const_string`
% facts by kbgen : the key `status` is captured as a bare identifier
% token, not a string constant. Adding the gate makes the predicate
% never fire in practice ( every real `Response.json({ status: ... })`
% call site regressed to zero matches before we dropped it -- see the
% `checkAuth` shape-recognizer CI investigation ).
%
% Loosening this to "the OUTER dict has SOME kv-arg whose value is a
% bad code" is still overwhelmingly specific in the presence of the
% `kb_call_resolved(_, 'nodejs.Response.json')` anchor : Response.json's
% second argument is always the init options bag, and int-valued kv
% pairs in that bag are almost exclusively `status`. If a future
% codebase abuses the second arg to carry an int-valued non-status
% field, promote the gate to the more permissive
% `kb_arg_i_for_call(KeyLoc, 0, KvCallLoc)` + name-carrying-fact
% variant ( currently requires a kbgen leaf-addition to emit the
% shorthand-identifier-key name ).
utils_ts_response_json_at_with_status(Call, Code) :-
    kb_call_resolved(Call, 'nodejs.Response.json'),
    kb_arg_i_for_call(DictifyCallLoc, 1, Call),
    kb_arg_i_for_call(KvCallLoc, _, DictifyCallLoc),
    kb_arg_i_for_call(ValueLoc, 1, KvCallLoc),
    kb_const_int(ValueLoc, Code).

% -----------------------------------------------------------------------------
% utils_authenticating_function_by_return_values( Callable )
%
% Structural sibling of `utils_authenticating_function_name/1` ( the tier-1
% NAME catalog above ). This predicate recognises a middleware-guard-shaped
% callable *by the values it returns* : exactly N bad-http returns plus
% exactly 1 "fall-through" return ( the parser-injected `return null`
% anchored at the callable's header location ). That signature IS the
% signature of a guard middleware -- every failing path emits an HTTP
% error, the single success path falls through implicitly.
%
% Design choice -- no `forall/2` :
% -------------------------------
% Instead of one open-ended clause "every non-fall-through return is bad",
% each candidate arity is enumerated as its own clause :
%
%     by_1v1_return_values : 1 bad + 1 fall-through  ( 2 returns total )
%     by_2v1_return_values : 2 bad + 1 fall-through  ( 3 returns total )
%     by_3v1_return_values : 3 bad + 1 fall-through  ( 4 returns total )
%     by_4v1_return_values : 4 bad + 1 fall-through  ( 5 returns total )
%
% Rationale :
%   1. Each shape is a ground rule the demo-driving LLM can inspect verbatim
%      -- no quantifier semantics to reason about.
%   2. The fall-through's position ( `ReturnedValue = Callable` ) is named
%      explicitly per shape instead of being derived post-hoc from a
%      quantifier.
%   3. Debuggability : a misfire on one shape is isolated to that clause.
%   4. Determinism : a K-return callable matches exactly one shape ( the
%      shape whose bad-count = K - 1 ), so query results dedup by
%      construction.
% Cost : O(N) clauses. For N = 4 that is four short clauses ; extension to
% higher arities is a pure leaf addition per clause.
%
% Fall-through convention ( set by the parser ) :
% ----------------------------------------------
%     Every callable body has a `return null` synthetically appended, whose
%     ReturnedValue location coincides with the callable's header location.
%     In Prolog that means `kb_callable_returns_value( F, F )` for exactly
%     one return of every well-formed callable. See
%     `TsParserActions.hs::ensureCallableBodyEndsWithReturn` for the
%     injection.
%
% Bare `return;` cardinality gate :
% --------------------------------
%     `kb_callable_returns_without_value( F, _ )` must be empty. Bare
%     returns are semantically equivalent to fall-throughs but break the
%     clean "N-bad + 1-fall-through" count. Guards that mix bare and value
%     returns are rare in practice ; leaf-add a dedicated shape family
%     here if a real-world case demands it.

utils_authenticating_function_by_return_values(F) :-
    utils_authenticating_function_by_1v1_return_values(F).
utils_authenticating_function_by_return_values(F) :-
    utils_authenticating_function_by_2v1_return_values(F).
utils_authenticating_function_by_return_values(F) :-
    utils_authenticating_function_by_3v1_return_values(F).
utils_authenticating_function_by_return_values(F) :-
    utils_authenticating_function_by_4v1_return_values(F).
% add more shape arities here ( by_5v1_return_values, by_6v1_return_values, ... ) ...

% Enumeration idiom -- `kb_callable_returns_value(F, F)` :
% ------------------------------------------------------
% Every clause below opens with `kb_callable_returns_value(F, F)`. That
% is NOT decorative -- it is what enumerates F over callables when the
% caller queries the shape predicate with F unbound ( eg
% `findall(F, utils_authenticating_function_by_return_values(F), _)` ).
%
% Without this leading goal, the subsequent `findall(R,
% kb_callable_returns_value(F, R), Returns)` would fire with an
% UNBOUND F -- Prolog's `findall/3` unifies R against every
% `kb_callable_returns_value(_, _)` fact in the KB, producing a single
% giant list mixed across ALL callables and never hitting the
% `length(Returns, K)` cardinality gate. That was the exact bug the
% initial CI run of this predicate surfaced ( MATCH_COUNT: 0 despite
% checkAuth being locally verified to fit the 3v1 shape ).
%
% `kb_callable_returns_value(F, F)` uses the parser-injected
% fall-through as the enumerator : every well-formed callable body has
% exactly one such fact where the ReturnedValue location coincides
% with the callable's own header location ( see
% `TsParserActions.hs::ensureCallableBodyEndsWithReturn` ). One fact
% per callable means F is enumerated ONCE per candidate -- no
% duplicate shape checks. Callables that lack a fall-through ( eg an
% AST that never went through `ensureCallableBodyEndsWithReturn` )
% are correctly excluded here : the shape predicate is only sound
% under the fall-through convention anyway.

% 1v1 : exactly 2 value-returns -- one is a bad-http response, the other is
% the parser-injected fall-through ( `ReturnedValue = Callable` ). No bare
% returns anywhere in the body.
utils_authenticating_function_by_1v1_return_values(F) :-
    kb_callable_returns_value(F, F),
    findall(R, kb_callable_returns_value(F, R), Returns),
    length(Returns, 2),
    \+ kb_callable_returns_without_value(F, _),
    select(F, Returns, [Bad1]),
    utils_return_value_is_bad_http_response(Bad1).

% 2v1 : exactly 3 value-returns -- two are bad-http responses, one is the
% parser-injected fall-through. No bare returns.
utils_authenticating_function_by_2v1_return_values(F) :-
    kb_callable_returns_value(F, F),
    findall(R, kb_callable_returns_value(F, R), Returns),
    length(Returns, 3),
    \+ kb_callable_returns_without_value(F, _),
    select(F, Returns, [Bad1, Bad2]),
    utils_return_value_is_bad_http_response(Bad1),
    utils_return_value_is_bad_http_response(Bad2).

% 3v1 : exactly 4 value-returns -- three are bad-http responses, one is the
% parser-injected fall-through. No bare returns.
utils_authenticating_function_by_3v1_return_values(F) :-
    kb_callable_returns_value(F, F),
    findall(R, kb_callable_returns_value(F, R), Returns),
    length(Returns, 4),
    \+ kb_callable_returns_without_value(F, _),
    select(F, Returns, [Bad1, Bad2, Bad3]),
    utils_return_value_is_bad_http_response(Bad1),
    utils_return_value_is_bad_http_response(Bad2),
    utils_return_value_is_bad_http_response(Bad3).

% 4v1 : exactly 5 value-returns -- four are bad-http responses, one is the
% parser-injected fall-through. No bare returns.
utils_authenticating_function_by_4v1_return_values(F) :-
    kb_callable_returns_value(F, F),
    findall(R, kb_callable_returns_value(F, R), Returns),
    length(Returns, 5),
    \+ kb_callable_returns_without_value(F, _),
    select(F, Returns, [Bad1, Bad2, Bad3, Bad4]),
    utils_return_value_is_bad_http_response(Bad1),
    utils_return_value_is_bad_http_response(Bad2),
    utils_return_value_is_bad_http_response(Bad3),
    utils_return_value_is_bad_http_response(Bad4).

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
