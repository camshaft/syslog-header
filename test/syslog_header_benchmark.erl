-module (syslog_header_benchmark).

-export ([test/1]).

test(Limit)->
  {ok, [Cases]} = file:consult("./test/frames.tests"),

  {Time, ok} = timer:tc(fun()-> loop(Cases, length(Cases), Limit, Limit) end),

  io:format("~p iterations in ~ps~n", [Limit, Time/1000000]),
  io:format("~p messages/sec~n", [Limit/(Time/1000000)]).

loop(_, _, 0, _)->
  ok;
loop(Cases, Length, Count, Limit) ->
  [syslog_header:parse(Case) || Case <- Cases],
  loop(Cases, Length, Count-Length, Limit).
