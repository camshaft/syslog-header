%%
%% syslog_header.erl
%%
%% http://tools.ietf.org/html/rfc5424#section-6
%%
-module (syslog_header).

-export([parse/1]).

-ifdef (TEST).
-export([parse_prefix/1]).
-export([parse_date/1]).
-export([parse_hostname/1]).
-export([parse_system/1]).
-endif.

%% @doc Parse a syslog header
%% @public
-spec parse(binary()) -> {ok, [{atom(), binary()}], binary()}.
parse(Frame)->
  case parse_prefix(Frame) of
    {ok, Priority, Version, Rest} ->
      case parse_date(Rest) of
        {ok, Timestamp, Rest2} ->
          case parse_hostname(Rest2) of
            {ok, Hostname, Rest3} ->
              case parse_system(Rest3) of
                {ok, AppName, ProcID, MessageID, Message} ->
                  construct_event(Priority, Version, Timestamp, Hostname, AppName, ProcID, MessageID, Message);
                _ -> {error, system}
              end;
            _ -> {error, drain}
          end;
        _ -> {error, date}
      end;
    _ -> {error, prefix}
  end.

construct_event(Priority, Version, Timestamp, Hostname, AppName, ProcID, MessageID, Message)->
  {ok, [
    {priority, Priority},
    {version, Version},
    {timestamp, Timestamp},
    {hostname, Hostname},
    {app_name, AppName},
    {proc_id, ProcID},
    {message_id, MessageID},
    {message, Message}
  ]}.

%% @doc prefix pattern
%% @example <140>1
-spec parse_prefix(binary()) -> {ok, integer(), integer()} | error.
parse_prefix(<<>>)->
  error;
parse_prefix(<<$<,D1,$>,Version," ",Rest/binary>>)->
  {ok, concat_int(D1), concat_int(Version), Rest};
parse_prefix(<<$<,D1,D2,$>,Version," ",Rest/binary>>)->
  {ok, concat_int(D1,D2), concat_int(Version), Rest};
parse_prefix(<<$<,D1,D2,D3,$>,Version," ",Rest/binary>>)->
  {ok, concat_int(D1,D2,D3), concat_int(Version), Rest};

parse_prefix(<<$<,D1,$>,V1,V2," ",Rest/binary>>)->
  {ok, concat_int(D1), concat_int(V1,V2), Rest};
parse_prefix(<<$<,D1,D2,$>,V1,V2," ",Rest/binary>>)->
  {ok, concat_int(D1,D2), concat_int(V1,V2), Rest};
parse_prefix(<<$<,D1,D2,D3,$>,V1,V2," ",Rest/binary>>)->
  {ok, concat_int(D1,D2,D3), concat_int(V1,V2), Rest};
parse_prefix(<<_,Rest/binary>>)->
  parse_prefix(Rest).

%% @doc date pattern
%% @example 2013-03-21T22:52:26+00:00
%% @todo handle timezones
-spec parse_date(binary()) -> {ok, calendar:datetime()} | error.
parse_date(<<>>)->
  error;
parse_date(<<Y1,Y2,Y3,Y4,$-,M1,M2,$-,D1,D2,$T,H1,H2,$:,Mn1,Mn2,$:,S1,S2,$+,_Tz1,_Tz2,$:,_Tz3,_Tz4," ",Rest/binary>>)->
  Time = {concat_int(H1,H2), concat_int(Mn1,Mn2), concat_int(S1,S2)},
  Date = {concat_int(Y1,Y2,Y3,Y4), concat_int(M1,M2), concat_int(D1,D2)},
  {ok, {Date, Time}, Rest};
parse_date(<<Y1,Y2,Y3,Y4,$-,M1,M2,$-,D1,D2,$T,H1,H2,$:,Mn1,Mn2,$:,S1,S2,$-,_Tz1,_Tz2,$:,_Tz3,_Tz4," ",Rest/binary>>)->
  Time = {concat_int(H1,H2), concat_int(Mn1,Mn2), concat_int(S1,S2)},
  Date = {concat_int(Y1,Y2,Y3,Y4), concat_int(M1,M2), concat_int(D1,D2)},
  {ok, {Date, Time}, Rest};
parse_date(<<_,Rest/binary>>)->
  parse_date(Rest).

%% @doc hostname pattern
%% @example d.de02fad5-ca75-4863-8d0a-de58404f9225
-spec parse_hostname(binary()) -> {ok, binary(), binary()} | error.
parse_hostname(<<>>)->
  error;
parse_hostname(Bin)->
  parse_hostname(Bin, <<>>).
parse_hostname(<<" ", Rest/binary>>, Acc)->
  {ok, Acc, Rest};
parse_hostname(<<C:1/binary, Rest/binary>>, Acc)->
  parse_hostname(Rest, <<Acc/binary,C/binary>>).

%% @doc app_name/proc_id pattern
%% @example heroku web.1 - -
-spec parse_system(binary()) -> {ok, binary(), binary()} | error.
parse_system(<<>>)->
  error;
parse_system(Bin)->
  find_app_name(Bin, <<>>).

find_app_name(<<" ",Rest/binary>>, <<>>=AppName)->
  find_app_name(Rest, AppName);
find_app_name(<<" ",Rest/binary>>, AppName)->
  find_proc_id(Rest, AppName, <<>>);
find_app_name(<<C:1/binary,Rest/binary>>, AppName)->
  find_app_name(Rest, <<AppName/binary,C/binary>>).

find_proc_id(<<" ",Rest/binary>>, AppName, <<>>=ProcID)->
  find_proc_id(Rest, AppName, ProcID);
find_proc_id(<<" ",Rest/binary>>, AppName, ProcID)->
  message_id(Rest, AppName, ProcID);
find_proc_id(<<C:1/binary,Rest/binary>>, AppName, ProcID)->
  find_proc_id(Rest, AppName, <<ProcID/binary,C/binary>>).

%% This is pretty messy... :/ - we get about 10,000 message/sec more with it
message_id(<<"- - ",Rest/binary>>, AppName, ProcID)->
  {ok, AppName, ProcID, undefined, Rest};
message_id(<<"- ",C:1/binary," - ",Rest/binary>>, AppName, ProcID)->
  {ok, AppName, ProcID, C, Rest};
message_id(<<"- ",C:2/binary," - ",Rest/binary>>, AppName, ProcID)->
  {ok, AppName, ProcID, C, Rest};
message_id(<<"- ",C:3/binary," - ",Rest/binary>>, AppName, ProcID)->
  {ok, AppName, ProcID, C, Rest};
message_id(<<"- ",C:4/binary," - ",Rest/binary>>, AppName, ProcID)->
  {ok, AppName, ProcID, C, Rest};
message_id(<<"- ",C:5/binary," - ",Rest/binary>>, AppName, ProcID)->
  {ok, AppName, ProcID, C, Rest};
message_id(<<"- ",C:6/binary," - ",Rest/binary>>, AppName, ProcID)->
  {ok, AppName, ProcID, C, Rest};
message_id(<<"- ",C:7/binary," - ",Rest/binary>>, AppName, ProcID)->
  {ok, AppName, ProcID, C, Rest};
message_id(<<"- ",C:8/binary," - ",Rest/binary>>, AppName, ProcID)->
  {ok, AppName, ProcID, C, Rest};
message_id(<<"- ",C:9/binary," - ",Rest/binary>>, AppName, ProcID)->
  {ok, AppName, ProcID, C, Rest};
message_id(<<"- ",C:10/binary," - ",Rest/binary>>, AppName, ProcID)->
  {ok, AppName, ProcID, C, Rest};
message_id(<<"- ",C:11/binary," - ",Rest/binary>>, AppName, ProcID)->
  {ok, AppName, ProcID, C, Rest};
message_id(<<"- ",C:12/binary," - ",Rest/binary>>, AppName, ProcID)->
  {ok, AppName, ProcID, C, Rest};
message_id(<<"- ",C:13/binary," - ",Rest/binary>>, AppName, ProcID)->
  {ok, AppName, ProcID, C, Rest};
message_id(<<"- ",C:14/binary," - ",Rest/binary>>, AppName, ProcID)->
  {ok, AppName, ProcID, C, Rest};
message_id(<<"- ",C:15/binary," - ",Rest/binary>>, AppName, ProcID)->
  {ok, AppName, ProcID, C, Rest};
message_id(<<"- ",C:16/binary," - ",Rest/binary>>, AppName, ProcID)->
  {ok, AppName, ProcID, C, Rest};
message_id(<<"- ",C:17/binary," - ",Rest/binary>>, AppName, ProcID)->
  {ok, AppName, ProcID, C, Rest};
message_id(<<"- ",C:18/binary," - ",Rest/binary>>, AppName, ProcID)->
  {ok, AppName, ProcID, C, Rest};
message_id(<<"- ",C:19/binary," - ",Rest/binary>>, AppName, ProcID)->
  {ok, AppName, ProcID, C, Rest};
message_id(<<"- ",C:21/binary," - ",Rest/binary>>, AppName, ProcID)->
  {ok, AppName, ProcID, C, Rest};
message_id(<<"- ",C:22/binary," - ",Rest/binary>>, AppName, ProcID)->
  {ok, AppName, ProcID, C, Rest};
message_id(<<"- ",C:23/binary," - ",Rest/binary>>, AppName, ProcID)->
  {ok, AppName, ProcID, C, Rest};
message_id(<<"- ",C:24/binary," - ",Rest/binary>>, AppName, ProcID)->
  {ok, AppName, ProcID, C, Rest};
message_id(<<"- ",C:25/binary," - ",Rest/binary>>, AppName, ProcID)->
  {ok, AppName, ProcID, C, Rest};
message_id(<<"- ",C:26/binary," - ",Rest/binary>>, AppName, ProcID)->
  {ok, AppName, ProcID, C, Rest};
message_id(<<"- ",C:27/binary," - ",Rest/binary>>, AppName, ProcID)->
  {ok, AppName, ProcID, C, Rest};
message_id(<<"- ",C:28/binary," - ",Rest/binary>>, AppName, ProcID)->
  {ok, AppName, ProcID, C, Rest};
message_id(<<"- ",C:29/binary," - ",Rest/binary>>, AppName, ProcID)->
  {ok, AppName, ProcID, C, Rest};
message_id(<<"- ",C:31/binary," - ",Rest/binary>>, AppName, ProcID)->
  {ok, AppName, ProcID, C, Rest};
message_id(<<"- ",C:32/binary," - ",Rest/binary>>, AppName, ProcID)->
  {ok, AppName, ProcID, C, Rest};
message_id(_, _, _)->
  error.

%% @doc concatenate integers
%% @private
concat_int(D)->
  D-$0.
concat_int(D1, D2)->
  (D1-$0)*10+(D2-$0).
concat_int(D1, D2, D3)->
  (D1-$0)*100+(D2-$0)*10+(D3-$0).
concat_int(D1, D2, D3, D4)->
  (D1-$0)*1000+(D2-$0)*100+(D3-$0)*10+(D4-$0).
