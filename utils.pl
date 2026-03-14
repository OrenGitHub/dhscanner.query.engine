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

arbitrary_file_write_intra(Path) :-
    utils_user_input(UserInput),
    utils_arbitrary_file_write(Arg),
    utils_dataflow_path(UserInput, Arg, Path).

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

utils_arbitrary_file_write(Arg) :- utils_arbitrary_file_write_nodejs(Arg).

utils_arbitrary_file_write_nodejs(Arg) :-
    kb_has_fqn(Call, 'fs/promises.writeFile'),
    kb_arg_i_for_call(Arg, 0, Call).

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
% add more kinds here ...

injection(Path) :- rce(Path).
injection(Path) :- sqli(Path).
% add more kinds here ...

ssrf(Path) :-
    utils_http_request(Call),
    utils_user_input(UserInput),
    utils_dataflow_path(UserInput, Call, Path).

utils_http_request(Call) :- utils_http_request_go(Call).
% add more kinds here ...

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
% add more web frameworks here ...

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

utils_dataflow_edge(U, V) :- kb_dataflow_edge(U, V).

utils_dataflow_edge(Arg, Param) :-
    kb_arg_for_call(Arg, Call),
    kb_has_fqn(Call, Fqn),
    kb_has_fqn(Callable, Fqn),
    kb_callable_has_param(Callable, Param).

utils_dataflow_edge(Arg, Param) :-
    kb_arg_for_call(Arg, Call),
    kb_last_fqn_part(Call, FqnPart),
    kb_last_fqn_part(Callable, FqnPart),
    kb_callable_has_param(Callable, Param).

utils_bounded_dataflow_path(A,B,N,[(A,B)]) :-
    N >= 1,
    utils_dataflow_edge(A,B).

utils_bounded_dataflow_path(A,B,N,[(A,C) | Path]) :-
    N >= 2,
    utils_dataflow_edge(A,C),
    N_MINUS_1 is N - 1,
    utils_bounded_dataflow_path(C,B,N_MINUS_1,Path).

utils_dataflow_path(U,V,Path) :- utils_bounded_dataflow_path(U,V,10,Path).
