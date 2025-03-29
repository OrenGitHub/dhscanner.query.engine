:- style_check(-singleton).

owasp_top_10(Path) :- injection(Path).
% add more kinds here ...

injection(Path) :- sqli(Path).
% add more kinds here ...

utils_no_dataflow_path(Src, Dst) :-
    \+ utils_bounded_dataflow_path(Src, Dst, 3, _).

utils_has_prepared_statement_fqn(PreparedStatement) :-
    kb_has_fqn(PreparedStatement, 'gorm.io/gorm/clause.OrderByColumn').
    % add more kinds here ...

utils_prepared_statement(PreparedStatement) :-
    kb_call(PreparedStatement),
    utils_has_prepared_statement_fqn(PreparedStatement).

sqli(Path) :-
    utils_user_input(UserInput),
    raw_sql_query(Call),
    utils_bounded_dataflow_path(UserInput, Call, 2, Path),
    utils_prepared_statement(PreparedStatement),
    utils_no_dataflow_path(UserInput, PreparedStatement).

raw_sql_query(Call) :-
    raw_sql_fqn(Fqn),
    kb_call(Call),
    kb_has_fqn(Call, Fqn).

raw_sql_fqn('github.com/layer5io/meshery/server/models.Provider.GetGenericPersister.Model.Preload.Where.Order').

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
% add more web frameworks here ...

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
    kb_has_fqn(Method, 'post'),
    kb_has_fqn_parts(Call, 0, ClassFqn),
    kb_has_fqn_parts(Call, 1, 'get_query_argument'),
    kb_class_name(Class, ClassFqn),
    kb_called_from_method(Call, Method),
    kb_call(Call),
    kb_method_of_class(Method, Class),
    utils_subclass_of(Class, 'tornado.web.RequestHandler').

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
    utils_subclass_of(Class, Super),
    kb_class_name(Super, 'ApplicationController' ).

utils_composer_laravel_post_handler(Call) :-
    kb_call(Call),
    kb_has_fqn(Call, 'composer.Illuminate.Support.Facades.Route.post').

utils_npm_express_post_handler(Call) :-
    kb_call(Call),
    kb_has_fqn(Call, 'npm.express.post').

utils_pip_gradio_button_click(Call) :-
    kb_call(Call),
    kb_has_fqn(Call, 'gradio.Button.click').

utils_bounded_subclass_of(Subclass,Super,N) :-
    N >= 1,
    kb_subclass_of(Subclass,Super).

utils_bounded_subclass_of(Subclass,Super,N) :-
    N >= 2,
    kb_subclass_of(Subclass,Class),
    N_MINUS_1 is N - 1,
    utils_bounded_subclass_of(Class,Super,N_MINUS_1).

utils_subclass_of(Subclass,Super) :- utils_bounded_subclass_of(Subclass,Super,2).

utils_dataflow_edge(U, V) :- kb_dataflow_edge(U, V).
utils_dataflow_edge(Arg, Param) :-
    kb_arg_for_call(Arg, Call),
    kb_has_fqn(Call, Fqn),
    kb_has_fqn(Callable, Fqn),
    kb_callable_has_param(Callable, Param).
utils_dataflow_edge(Callable, Call) :-
    kb_callable(Callable),
    kb_call(Call),
    kb_has_fqn(Callable, Fqn),
    kb_has_fqn(Call, Fqn).

utils_bounded_dataflow_path(A,B,N,[(A,B)]) :-
    N >= 1,
    utils_dataflow_edge(A,B).

utils_bounded_dataflow_path(A,B,N,[(A,C) | Path]) :-
    N >= 2,
    utils_dataflow_edge(A,C),
    N_MINUS_1 is N - 1,
    utils_bounded_dataflow_path(C,B,N_MINUS_1,Path).

utils_dataflow_path(U,V,Path) :- utils_bounded_dataflow_path(U,V,30,Path).
