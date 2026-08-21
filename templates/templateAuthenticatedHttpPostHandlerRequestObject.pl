:- style_check(-singleton).
:- discontiguous utils_http_post_handler_request_object/3.
:- discontiguous utils_authenticated_http_post_handler_request_object/5.

:- dynamic kb_called_from/2.
:- dynamic kb_call_1st_party_func_defined_in_file/3.
:- dynamic kb_call_1st_party_func_defined_in_dir/3.

:- [ '{KNOWLEDGE_BASE}' ].
:- [ 'utils.pl' ].
:- use_module(library(solution_sequences)).

main :-
    Limit = {LIMIT},
    findnsols(
        Limit,
        (PostHandler, Request, Url, AuthFuncName, HeaderKey),
        (
            utils_authenticated_http_post_handler_request_object(PostHandler, Request, Url, AuthFuncName, HeaderKey)
        ),
        Matches
    ),
    print_matches(Matches).

print_matches([]) :- !.
print_matches([(PostHandler, Request, Url, AuthFuncName, HeaderKey)|Tail]) :-
    format("PostHandler(~q)~nRequest(~q)~nUrl(~q)~nAuthFuncName(~q)~nHeaderKey(~q)~n~n",
           [PostHandler, Request, Url, AuthFuncName, HeaderKey]),
    print_matches(Tail).
