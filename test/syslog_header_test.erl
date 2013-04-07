-module (syslog_header_test).

-include_lib("eunit/include/eunit.hrl").

-define (PARSE_TESTS, [
  {
    <<"<158>1 2013-03-21T22:55:51+00:00 d.de02fad5-ca75-4863-8d0a-de58404f9225 heroku router - - at=info method=GET path=/ host=my-cool-test.herokuapp.com request_id=755159ef5cfc715185a43e664d0be6c8 fwd=\"216.49.181.254, 204.9.229.1\" dyno=web.1 queue=0 wait=0ms connect=1ms service=364ms status=200 bytes=20946\n">>,
    [
      {priority, 158},
      {version, 1},
      {timestamp, {{2013,03,21},{22,55,51}}},
      {hostname, <<"d.de02fad5-ca75-4863-8d0a-de58404f9225">>},
      {app_name, <<"heroku">>},
      {proc_id, <<"router">>},
      {message_id, undefined},
      {message, <<"at=info method=GET path=/ host=my-cool-test.herokuapp.com request_id=755159ef5cfc715185a43e664d0be6c8 fwd=\"216.49.181.254, 204.9.229.1\" dyno=web.1 queue=0 wait=0ms connect=1ms service=364ms status=200 bytes=20946\n">>}
    ]
  },
  {
    <<"<40>12 2013-03-21T22:52:26+00:00 d.de02fad5-ca75-4863-8d0a-de58404f9225 heroku web.1 - - source=heroku.6041702.web.1.dabb0da6-d9d5-4627-a299-0b218adf1d3e measure=load_avg_1m val=0.00\n">>,
    [
      {priority, 40},
      {version, 12},
      {timestamp, {{2013,03,21},{22,52,26}}},
      {hostname, <<"d.de02fad5-ca75-4863-8d0a-de58404f9225">>},
      {app_name, <<"heroku">>},
      {proc_id, <<"web.1">>},
      {message_id, undefined},
      {message, <<"source=heroku.6041702.web.1.dabb0da6-d9d5-4627-a299-0b218adf1d3e measure=load_avg_1m val=0.00\n">>}
    ]
  }
]).

parse_test_()->
  [fun() -> run_parse_test(Test) end || Test <- ?PARSE_TESTS].
run_parse_test({Message, Expected})->
  {ok, Msg} = syslog_header:parse(Message),
  ?assertEqual(Expected, Msg).
