:- style_check(-singleton).

%problems(_) :- utils_user_input_originated_from_go_bone_negroni_http_request_handler(_).

problems(Path) :- owasp_top_10(Path).
problems(Path) :- file_deletion(Path).
problems(Path) :- unsafe_deserialization(Path).
problems(Path) :- arbitrary_file_read(Path).
problems(Path) :- arbitrary_file_write(Path).
problems(Path) :- open_redirect(Path).
problems(Path) :- broken_access_control(Path).
% add more kinds here ...

broken_access_control(Path) :- broken_access_control_php_wordpress_plugin(Path).
% add more kinds here ...

wordpress_entrypoint_fqn(Call) :- kb_has_fqn(Call, 'add_action').
wordpress_entrypoint_fqn(Call) :- kb_has_fqn(Call, 'add_submenu_page').

wordpress_sink_fqn(Call) :- wordpress_sink_fqn_wp_trash_post(Call).

wordpress_sink_fqn_wp_trash_post(Call) :-
    kb_const_string(Callee, 'wp_trash_post'),
    kb_has_fqn(Call, 'array_map'),
    kb_arg_i_for_call(Callee, 0, Call).

broken_access_control_php_wordpress_plugin(Path) :-
    wordpress_entrypoint_fqn(Call),
    wordpress_sink_fqn(Target),
    kb_call(Call),
    kb_arg_i_for_call(Arg, 5, Call),
    kb_has_fqn(Arg, Fqn),
    kb_callable(Callable),
    kb_has_fqn(Callable, Fqn),
    kb_call(Target),
    utils_control_flow_no_csrf_check_path(Callable, Target, Path).

open_redirect(Path) :-
    kb_has_fqn(Target, 'window'),
    utils_user_input(UserInput),
    utils_dataflow_path(UserInput, Target, Path).

open_redirect(Path) :-
    utils_subclass_of(Class, 'tornado.web.RequestHandler'),
    kb_has_fqn_parts(Call, 1, 'redirect'),
    kb_has_fqn_parts(Call, 0, ClassFqn),
    kb_class_name(Class, ClassFqn),
    utils_user_input(UserInput),
    utils_dataflow_path(UserInput, Call, Path).

arbitrary_file_read(Path) :-
    utils_user_input(UserInput),
    kb_has_fqn(Call, 'flask.send_file'),
    utils_dataflow_path(UserInput, Call, Path).

arbitrary_file_write(Path) :-
    utils_user_input(UserInput),
    kb_has_fqn(Call, 'fs/promises.writeFile'),
    kb_arg_i_for_call(Arg, 0, Call),
    utils_dataflow_path(UserInput, Arg, Path).

unsafe_deserialization(Path) :-
    utils_user_input(UserInput),
    unsafe_deserialization_call(Call),
    utils_dataflow_path(UserInput, Call, Path).

unsafe_deserialization_call(Call) :- unsafe_deserialization_call_ruby(Call).
% add more kinds here ...

unsafe_deserialization_call_ruby(Call) :-
    kb_has_fqn(Call, 'YAML.load_stream'),
    kb_call(Call).

file_deletion(Path) :- file_deletion_golang(Path).

file_deletion_golang(Path) :-
    kb_has_fqn(Call, 'os.Remove'),
    utils_user_input(UserInput),
    kb_call(Call),
    utils_dataflow_path(UserInput, Call, Path).

owasp_top_10(Path) :- injection(Path).
owasp_top_10(Path) :- ssrf(Path).
% add more kinds here ...

injection(Path) :- rce(Path).
injection(Path) :- sqli(Path).
% add more kinds here ...

ssrf(Path) :-
    utils_user_input(UserInput),
    utils_http_request(Call),
    utils_dataflow_path(UserInput, Call, Path).

utils_http_request(Call) :-
    kb_has_fqn(Call, 'requests.post'),
    kb_call(Call).

rce(Path) :-
    utils_user_input(UserInput),
    utils_cmd_exec(Call),
    utils_dataflow_path(UserInput, Call, Path).

utils_cmd_exec(Call) :- utils_cmd_exec_go(Call).

utils_cmd_exec_go(Call) :-
    kb_has_fqn(Call, 'os/exec.CommandContext'),
    kb_call(Call).

utils_cmd_exec_go(Call) :-
    kb_has_fqn(Call, 'os/exec.Command'),
    kb_call(Call).

utils_has_prepared_statement_fqn(PreparedStatement) :-
    kb_has_fqn(PreparedStatement, 'gorm.io/gorm/clause.OrderByColumn').
    % add more kinds here ...

utils_prepared_statement(PreparedStatement) :-
    kb_call(PreparedStatement),
    utils_has_prepared_statement_fqn(PreparedStatement).

utils_shorter_prepared_statement_dataflow_path(Src, Dst, MaxLength) :-
    utils_bounded_dataflow_path(Src, Dst, MaxLength, _).

sqli(Path) :- sqli_php(Path).
% add more kinds here ...

sqli_php(Path) :- sqli_php_yii(Path).
% add more kinds here ...

sqli_php_yii(Path) :-
    kb_has_fqn(Call, 'Yii.app.db.createCommand.queryAll'),
    kb_call(Call),
    utils_user_input(UserInput),
    utils_dataflow_path(UserInput, Call, Path).

user_input_might_be_assigned_to(Fqn, Path) :-
    kb_has_fqn(Target, Fqn),
    utils_user_input(UserInput),
    utils_dataflow_path(UserInput, Target, Path).

user_input_might_reach_function(Fqn, Path) :-
    kb_call(Call),
    kb_has_fqn(Call, Fqn),
    utils_user_input(UserInput),
    utils_dataflow_path(UserInput, Call, Path).

user_input_might_reach_function_parts(FqnPart0, FqnPart1, Path) :-
    kb_call(Call),
    kb_has_fqn_parts(Call, 1, FqnPart1),
    utils_user_input(UserInput),
    utils_dataflow_path(UserInput, Call, Path).

utils_user_input(UserInput) :- utils_user_input_originated_from_npm_express_post_request_params(UserInput).
utils_user_input(UserInput) :- utils_user_input_originated_from_composer_laravel_post_request_params(UserInput).
utils_user_input(UserInput) :- utils_user_input_originated_from_pip_gradio_button_click_dispatch(UserInput).
utils_user_input(UserInput) :- utils_user_input_originated_from_ruby_rails_post_request_params(UserInput).
utils_user_input(UserInput) :- utils_user_input_originated_from_php_wordpress_plugin_action(UserInput).
utils_user_input(UserInput) :- utils_user_input_originated_from_pip_fastapi_get_request_params(UserInput).
utils_user_input(UserInput) :- utils_user_input_originated_from_pip_tornado_get_query_argument(UserInput).
utils_user_input(UserInput) :- utils_user_input_originated_from_js_url_search_params(UserInput).
utils_user_input(UserInput) :- utils_user_input_originated_from_go_gin_query_params(UserInput).
utils_user_input(UserInput) :- utils_user_input_originated_from_go_native_parser_query_params(UserInput).
utils_user_input(UserInput) :- utils_user_input_originated_from_pip_flask_route_param(UserInput).
utils_user_input(UserInput) :- utils_user_input_originated_from_js_react_location(UserInput).
utils_user_input(UserInput) :- utils_user_input_originated_from_pip_django_views(UserInput).
utils_user_input(UserInput) :- utils_user_input_originated_from_php_yii_query_params(UserInput).
utils_user_input(UserInput) :- utils_user_input_originated_from_nextjs_http_post_request_handler(UserInput).
utils_user_input(UserInput) :- utils_user_input_originated_from_go_bone_negroni_http_request_handler(UserInput).
% add more web frameworks here ...

utils_user_input_originated_from_go_bone_negroni_http_request_handler(Param) :-
    kb_has_fqn(RegisterRouteCall, 'github.com/go-zoo/bone.Mux.Put'),
    kb_has_fqn(NegroniNew, 'github.com/codegangsta/negroni.New'),
    kb_has_fqn(Handler, 'github.com/codegangsta/negroni.HandlerFunc'),
    kb_param_has_type(Param, 'net/http.Request'),
    kb_param_has_name(Param, 'req'),
    kb_arg_i_for_call(Route, 0, RegisterRouteCall),
    kb_arg_i_for_call(NegroniNew, 1, RegisterRouteCall),
    kb_arg_i_for_call(Handler, 1, NegroniNew),
    kb_arg_i_for_call(DispatchedCallee, 0, Handler),
    kb_has_fqn(DispatchedCallee, Fqn),
    kb_has_fqn(Callee, Fqn),
    kb_callable_has_param(Callee, Param),
    kb_const_string(Route, _),
    write('[DEBUG] Found Param: '), write(Param), nl.
    %write('[DEBUG] Found Handler: '), write(Handler), nl,
    %write('[DEBUG] Found Route: '), write(Route), nl,
    %write('[DEBUG] Found DispatchedCallee: '), write(DispatchedCallee), nl,
    %write('[DEBUG] Found Fqn: '), write(Fqn), nl,
    %write('[DEBUG] Found Callee: '), write(Callee), nl.

utils_user_input_originated_from_nextjs_http_post_request_handler(Param) :-
    kb_param_has_type(Param, 'next/server.NextRequest'),
    kb_has_fqn(Callable, 'POST'),
    kb_callable_has_param(Callable, Param).

utils_user_input_originated_from_php_yii_query_params(UserInput) :-
    kb_has_fqn(UserInput, 'Yii.app.getRequest.getQueryParam'),
    kb_call(UserInput).

utils_user_input_originated_from_pip_django_views(UserInput) :-
    kb_callable_annotated_with(Callable, 'django.views.decorators.http.require_http_methods'),
    kb_param_has_name(UserInput, 'request'),
    kb_callable_has_param(Callable, UserInput).

utils_user_input_originated_from_go_native_http_request_handler(UserInput) :-
    kb_has_fqn(Call, 'net/http.HandleFunc'),
    kb_arg_for_call(Route, Call),
    kb_const_string(Route, _),
    kb_arg_for_call(Lambda, Call),
    kb_callable(Lambda),
    kb_callable_has_param(Lambda, Response),
    kb_param_has_type(Response, 'net/http.ResponseWriter'),
    kb_callable_has_param(Lambda, UserInput),
    kb_param_has_type(UserInput, 'net/http.Request').

utils_user_input_originated_from_js_react_location(UserInput) :-
    kb_has_fqn(UserInput, 'react-router-dom.useLocation'),
    kb_call(UserInput).

utils_user_input_originated_from_pip_flask_route_param(UserInput) :-
    kb_callable_annotated_with(Callable, 'flask.Blueprint.route'),
    kb_callable_annotated_with_user_input_inside_route(Callable, RouteParam),
    kb_callable_has_param(Callable, UserInput),
    kb_param_has_name(UserInput, RouteParam).

utils_user_input_originated_from_go_native_http_request_body(UserInput) :-
    kb_has_fqn(UserInput, 'net/http.Request.Body').

utils_user_input_originated_from_go_native_parser_query_params(UserInput) :-
    kb_has_fqn(UserInput, 'net/http.Request.URL.Query.Get'),
    kb_call(UserInput).

utils_user_input_originated_from_go_gin_query_params(UserInput) :-
    kb_has_fqn(UserInput, 'github.com/gin-gonic/gin.Context.Param'),
    kb_call(UserInput).

utils_user_input_originated_from_js_url_search_params(UserInput) :-
    kb_has_fqn(UserInput, 'URLSearchParams.get'),
    kb_call(UserInput).

utils_user_input_originated_from_pip_tornado_get_query_argument(Call) :-
    utils_subclass_of(Class, 'tornado.web.RequestHandler'),
    kb_has_fqn_parts(Call, 1, 'get_query_argument'),
    kb_has_fqn_parts(Call, 0, ClassFqn),
    kb_has_fqn(Method, 'post'),
    kb_called_from_method(Call, Method),
    kb_class_name(Class, ClassFqn),
    kb_method_of_class(Method, Class),
    kb_call(UserInput).

% note: array(some, 5, 'vars') modeled as: arrayify(some, 5, 'vars')
% example: (CVE-2024-7856)
% code: add_action('wp_ajax_removeTempFiles', array($this, 'removeTempFiles'));
% method: --------------------------------------------------^^^^^^^^^^^^^^^
utils_user_input_originated_from_php_wordpress_plugin_action(UserInput) :-
    kb_call(WordpressAction),
    kb_has_fqn(WordpressAction,'add_action'),
    kb_arg_for_call(ConstArray,WordpressAction),
    kb_call(ConstArray),
    kb_has_fqn(ConstArray,'arrayify'),
    kb_arg_for_call(Callback,ConstArray),
    kb_const_string(Callback,Fqn),
    kb_has_fqn(Method, Fqn),
    kb_var_in_method(UserInput, Method),
    kb_has_fqn(UserInput, 'filter_input').

utils_user_input_originated_from_pip_fastapi_get_request_params(UserInput) :-
    kb_callable(Callable),
    kb_callable_annotated_with(Calleble, 'fastapi.APIRouter.get'),
    kb_callable_has_param(Callable, UserInput).

utils_user_input_originated_from_pip_fastapi_get_request_params(UserInput) :-
    kb_callable(Callable),
    kb_callable_annotated_with(Calleble, 'fastapi.FastAPI.get'),
    kb_callable_has_param(Callable, UserInput).

utils_user_input_originated_from_composer_laravel_post_request_params(UserInput) :-
    utils_composer_laravel_post_handler(Call),
    kb_arg_for_call(Callback, Call),
    kb_callable(Callback),
    kb_callable_has_param(Callback, UserInput),
    kb_param_has_name(UserInput, 'request').

utils_user_input_originated_from_npm_express_post_request_params(UserInput) :-
    utils_npm_express_post_handler(Call),
    kb_arg_for_call(Callback, Call),
    kb_callable(Callback),
    kb_callable_has_param(Callback, UserInput),
    kb_param_has_name(UserInput, 'req').

utils_user_input_originated_from_pip_gradio_button_click_dispatch(UserInput) :-
    utils_pip_gradio_button_click(Call),
    kb_arg_for_call(Callback, Call),
    kb_callable(Callback),
    kb_callable_has_param(Callback, UserInput).

utils_user_input_originated_from_ruby_rails_post_request_params(UserInput) :-
    kb_has_fqn(UserInput, 'params'),
    utils_ruby_rails_class_controller(Class),
    kb_var_in_method(UserInput, Method),
    kb_method_of_class(Method, Class).

utils_ruby_rails_class_controller(Class) :-
    kb_subclass_of(Class, 'ApplicationController' ).

utils_ruby_rails_class_controller(Class) :-
    kb_subclass_of(Super, 'ApplicationController' ),
    kb_class_name(Super, Name),
    kb_subclass_of(Class, Name).

utils_composer_laravel_post_handler(Call) :-
    kb_call(Call),
    kb_has_fqn(Call, 'composer.Illuminate.Support.Facades.Route.post').

utils_npm_express_post_handler(Call) :-
    kb_call(Call),
    kb_has_fqn(Call, 'npm.express.post').

utils_pip_gradio_button_click(Call) :-
    kb_call(Call),
    kb_has_fqn(Call, 'gradio.Button.click').

utils_bounded_subclass_of(Class,SuperFqn,N) :-
    N >= 1,
    kb_subclass_of(Class,SuperFqn).

utils_bounded_subclass_of(Subclass,SuperFqn,N) :-
    N >= 2,
    kb_subclass_of(Subclass,ClassFqn),
    kb_class_name(Class, ClassFqn),
    N_MINUS_1 is N - 1,
    utils_bounded_subclass_of(Class,SuperFqn,N_MINUS_1).

utils_subclass_of(Subclass,Super) :- utils_bounded_subclass_of(Subclass,Super,2).

utils_control_flow_no_csrf_check_path(Src, Dst, Path) :-
    utils_bounded_control_flow_no_csrf_check_path(Src, Dst, 15, Path).

utils_bounded_control_flow_no_csrf_check_path(Src, Dst, N, [(Src, Dst)]) :-
    N >= 1,
    utils_control_flow_no_csrf_check_edge(Src, Dst).

utils_bounded_control_flow_no_csrf_check_path(Src, Dst, N, [(Src, Middle) | Path]) :-
    N >= 2,
    utils_control_flow_no_csrf_check_edge(Src, Middle),
    N_MINUS_1 is N - 1,
    utils_bounded_control_flow_no_csrf_check_path(Middle, Dst, N_MINUS_1, Path).

utils_csrf_check(Call) :-
    kb_has_fqn(Call, 'wp_verify_nonce'),
    kb_const_string(Subscript, '_wpnonce'),
    kb_has_fqn(Var, '_REQUEST'),
    kb_arg_i_for_call(Arg, 0, Call),
    kb_read_subscript(Arg, Var, Subscript).

utils_control_flow_no_csrf_check_edge(U, V) :-
    kb_control_flow_edge(U, V),
    \+ utils_csrf_check(U),
    \+ utils_csrf_check(V).

utils_control_flow_no_csrf_check_edge(Call, Callee) :-
    kb_has_fqn(Call, Fqn),
    kb_has_fqn(Callee, Fqn),
    kb_call(Call),
    kb_callable(Callee).

% wordpress dynamic construction of names:
%
%                           resolved  unknown
%                              |---|  |-----|
% call_user_func_array( array( $this, $method )
%
utils_control_flow_no_csrf_check_edge(FuncArray, Callee) :-
    kb_has_fqn(FuncArray, 'call_user_func_array'),
    kb_has_fqn(Call, 'arrayify'),
    kb_arg_i_for_call(Call, 0, FuncArray),
    kb_arg_i_for_call(This, 0, Call),
    kb_has_fqn(This, Fqn),
    kb_has_fqn_parts(Callee, 0, Fqn),
    kb_callable(Callee).

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

utils_dataflow_edge(Arg, Receiver) :-
    current_predicate(kb_var_in_method/2),
    kb_has_fqn(Receiver, 'ampersand'),
    kb_has_fqn_parts(Call, 0, 'ampersand'),
    kb_var_in_method(Receiver, Method),
    kb_called_from(Call, Method),
    kb_arg_for_call(Arg, Call),
    Arg \= Receiver.

utils_dataflow_edge(Call, Callable) :-
    kb_call(Call),
    kb_callable(Callable),
    kb_last_fqn_part(Call, Fqn),
    kb_has_fqn(Callable, Fqn).

%utils_dataflow_edge(Call, Callable) :-
%    kb_call(Call),
%    kb_callable(Callable),
%    kb_last_fqn_part(Call, FqnPart),
%    kb_last_fqn_part(Callable, FqnPart).

utils_dataflow_edge(Method, InsideMethodCall) :-
    kb_callable(Method),
    kb_called_from(InsideMethodCall, Method),
    kb_has_fqn_parts(Method, 0, FqnPart),
    kb_has_fqn_parts(InsideMethodCall, 0, FqnPart).

utils_dataflow_edge(Method, DataMember) :-
    current_predicate(kb_var_in_method/2),
    kb_callable(Method),
    kb_var_in_method(DataMember, Method),
    kb_has_fqn_parts(Method, 0, FqnPart),
    kb_has_fqn_parts(DataMember, 0, FqnPart).

utils_dataflow_edge(Call, Arg) :-
    kb_has_fqn(Call, 'encoding/json.NewDecoder.Decode'),
    kb_call(Call),
    kb_arg_for_call(Arg, Call).

utils_dataflow_edge(ArgIn, ArgOut) :-
    kb_has_fqn(Call, 'encoding/json.Unmarshal'),
    kb_arg_for_call(ArgIn, Call),
    kb_arg_for_call(ArgOut, Call).

utils_dataflow_edge(ArgIn, ArgOut) :-
    kb_has_fqn(Unmarshal, 'encoding/json.Unmarshal'),
    kb_called_from(Unmarshal, Callable),
    kb_has_fqn(Ampersand, 'ampersand'),
    kb_call(Ampersand),
    kb_arg_i_for_call(ArgOut, 0, Ampersand),
    kb_arg_for_call(ArgIn, Call),
    kb_arg_for_call(Ampersand, Call),
    kb_has_fqn_parts(Call, _, Fqn),
    kb_has_fqn(Callable, Fqn),
    ArgIn \= Ampersand.

%utils_dataflow_edge(Arg, Receiver) :-
%    kb_has_fqn(Receiver, 'ampersand'),
%    kb_has_fqn_parts(Call, 0, 'ampersand'),
%    kb_dataflow_edge(Receiver, Callee),
%    kb_dataflow_edge(Callee, Call),
%    kb_var_in_method(Receiver, Method),
%    kb_called_from(Call, Method),
%    kb_arg_for_call(Arg, Call).

utils_bounded_dataflow_path(A,B,N,[(A,B)]) :-
    N >= 1,
    utils_dataflow_edge(A,B).

utils_bounded_dataflow_path(A,B,N,[(A,C) | Path]) :-
    N >= 2,
    utils_dataflow_edge(A,C),
    N_MINUS_1 is N - 1,
    utils_bounded_dataflow_path(C,B,N_MINUS_1,Path).

utils_dataflow_path(U,V,Path) :- utils_bounded_dataflow_path(U,V,15,Path).