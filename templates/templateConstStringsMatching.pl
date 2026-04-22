:- style_check(-singleton).
:- discontiguous kb_const_string/2.
:- [ '{KNOWLEDGE_BASE}' ].
:- use_module(library(pcre)).
:- use_module(library(solution_sequences)).

main :-
    Regex = "{REGEX}",
    Limit = {LIMIT},
    findnsols(
        Limit,
        (Location, Match),
        (
            kb_const_string(Location, Match),
            re_match(Regex, Match, [])
        ),
        Matches
    ),
    print_matches(Matches).

print_matches([]) :- !.
print_matches([(Location, Match)|Tail]) :-
    format("(~q,~q)~n", [Location, Match]),
    print_matches(Tail).
