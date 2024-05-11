:- [ kb ].    % entire source code as prolog knowledge base
:- [ utils ]. % repetitive elements for *many* scanners

% replace with the actual cve
cve(_) :- template_cve.

main :- (cve(_) -> write('yes\n') ; write('no\n')).
