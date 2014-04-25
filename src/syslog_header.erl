%%
%% syslog_header.erl
%%
%% http://tools.ietf.org/html/rfc5424#section-6
%%
-module (syslog_header).

-type priority() :: pos_integer().
-type version() :: pos_integer().
-type hostname() :: binary().
-type app_name() :: binary().
-type proc_id() :: binary().
-type message_id() :: binary().
-type message() :: binary().
-type header() :: {priority(), version(), calendar:datetime(), hostname(), app_name(), proc_id(), message_id(), message()}.

-export([parse/1]).

%% @doc Parse a syslog header
%% @public
-spec parse(binary()) -> {ok, header()} | {error, term()}.
parse(Frame)->
  case parse_prefix(Frame) of
    {ok, Priority, Version, Rest} ->
      case parse_date(Rest) of
        {ok, Timestamp, Rest2} ->
          case parse_hostname(Rest2) of
            {ok, Hostname, Rest3} ->
              case parse_app_name(Rest3) of
                {ok, AppName, Rest4} ->
                  case parse_proc_id(Rest4) of
                    {ok, ProcID, Rest5} ->
                      case parse_message_id(Rest5) of
                        {ok, MessageID, Message} ->
                          {ok, {Priority, Version, Timestamp, Hostname, AppName, ProcID, MessageID, Message}};
                        _ -> {error, message_id}
                      end;
                    _ -> {error, proc_id}
                  end;
                _ -> {error, app_name}
              end;
            _ -> {error, drain}
          end;
        _ -> {error, date}
      end;
    _ -> {error, prefix}
  end.

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

% +
parse_date(<<Y1,Y2,Y3,Y4,$-,M1,M2,$-,D1,D2,$T,H1,H2,$:,Mn1,Mn2,$:,S1,S2,$+,_Tz1,_Tz2,$:,_Tz3,_Tz4," ",Rest/binary>>)->
  Time = {concat_int(H1,H2), concat_int(Mn1,Mn2), concat_int(S1,S2)},
  Date = {concat_int(Y1,Y2,Y3,Y4), concat_int(M1,M2), concat_int(D1,D2)},
  {ok, {Date, Time}, Rest};
parse_date(<<Y1,Y2,Y3,Y4,$-,M1,M2,$-,D1,D2,$T,H1,H2,$:,Mn1,Mn2,$:,S1,S2,$.,_MS1,$+,_Tz1,_Tz2,$:,_Tz3,_Tz4," ",Rest/binary>>)->
  Time = {concat_int(H1,H2), concat_int(Mn1,Mn2), concat_int(S1,S2)},
  Date = {concat_int(Y1,Y2,Y3,Y4), concat_int(M1,M2), concat_int(D1,D2)},
  {ok, {Date, Time}, Rest};
parse_date(<<Y1,Y2,Y3,Y4,$-,M1,M2,$-,D1,D2,$T,H1,H2,$:,Mn1,Mn2,$:,S1,S2,$.,_MS1,_MS2,$+,_Tz1,_Tz2,$:,_Tz3,_Tz4," ",Rest/binary>>)->
  Time = {concat_int(H1,H2), concat_int(Mn1,Mn2), concat_int(S1,S2)},
  Date = {concat_int(Y1,Y2,Y3,Y4), concat_int(M1,M2), concat_int(D1,D2)},
  {ok, {Date, Time}, Rest};
parse_date(<<Y1,Y2,Y3,Y4,$-,M1,M2,$-,D1,D2,$T,H1,H2,$:,Mn1,Mn2,$:,S1,S2,$.,_MS1,_MS2,_MS3,$+,_Tz1,_Tz2,$:,_Tz3,_Tz4," ",Rest/binary>>)->
  Time = {concat_int(H1,H2), concat_int(Mn1,Mn2), concat_int(S1,S2)},
  Date = {concat_int(Y1,Y2,Y3,Y4), concat_int(M1,M2), concat_int(D1,D2)},
  {ok, {Date, Time}, Rest};
parse_date(<<Y1,Y2,Y3,Y4,$-,M1,M2,$-,D1,D2,$T,H1,H2,$:,Mn1,Mn2,$:,S1,S2,$.,_MS1,_MS2,_MS3,_MS4,$+,_Tz1,_Tz2,$:,_Tz3,_Tz4," ",Rest/binary>>)->
  Time = {concat_int(H1,H2), concat_int(Mn1,Mn2), concat_int(S1,S2)},
  Date = {concat_int(Y1,Y2,Y3,Y4), concat_int(M1,M2), concat_int(D1,D2)},
  {ok, {Date, Time}, Rest};
parse_date(<<Y1,Y2,Y3,Y4,$-,M1,M2,$-,D1,D2,$T,H1,H2,$:,Mn1,Mn2,$:,S1,S2,$.,_MS1,_MS2,_MS3,_MS4,_MS5,$+,_Tz1,_Tz2,$:,_Tz3,_Tz4," ",Rest/binary>>)->
  Time = {concat_int(H1,H2), concat_int(Mn1,Mn2), concat_int(S1,S2)},
  Date = {concat_int(Y1,Y2,Y3,Y4), concat_int(M1,M2), concat_int(D1,D2)},
  {ok, {Date, Time}, Rest};
parse_date(<<Y1,Y2,Y3,Y4,$-,M1,M2,$-,D1,D2,$T,H1,H2,$:,Mn1,Mn2,$:,S1,S2,$.,_MS1,_MS2,_MS3,_MS4,_MS5,_MS6,$+,_Tz1,_Tz2,$:,_Tz3,_Tz4," ",Rest/binary>>)->
  Time = {concat_int(H1,H2), concat_int(Mn1,Mn2), concat_int(S1,S2)},
  Date = {concat_int(Y1,Y2,Y3,Y4), concat_int(M1,M2), concat_int(D1,D2)},
  {ok, {Date, Time}, Rest};
parse_date(<<Y1,Y2,Y3,Y4,$-,M1,M2,$-,D1,D2,$T,H1,H2,$:,Mn1,Mn2,$:,S1,S2,$.,_MS1,_MS2,_MS3,_MS4,_MS5,_MS6,_MS7,$+,_Tz1,_Tz2,$:,_Tz3,_Tz4," ",Rest/binary>>)->
  Time = {concat_int(H1,H2), concat_int(Mn1,Mn2), concat_int(S1,S2)},
  Date = {concat_int(Y1,Y2,Y3,Y4), concat_int(M1,M2), concat_int(D1,D2)},
  {ok, {Date, Time}, Rest};
parse_date(<<Y1,Y2,Y3,Y4,$-,M1,M2,$-,D1,D2,$T,H1,H2,$:,Mn1,Mn2,$:,S1,S2,$.,_MS1,_MS2,_MS3,_MS4,_MS5,_MS6,_MS7,_MS8,$+,_Tz1,_Tz2,$:,_Tz3,_Tz4," ",Rest/binary>>)->
  Time = {concat_int(H1,H2), concat_int(Mn1,Mn2), concat_int(S1,S2)},
  Date = {concat_int(Y1,Y2,Y3,Y4), concat_int(M1,M2), concat_int(D1,D2)},
  {ok, {Date, Time}, Rest};

% -
parse_date(<<Y1,Y2,Y3,Y4,$-,M1,M2,$-,D1,D2,$T,H1,H2,$:,Mn1,Mn2,$:,S1,S2,$-,_Tz1,_Tz2,$:,_Tz3,_Tz4," ",Rest/binary>>)->
  Time = {concat_int(H1,H2), concat_int(Mn1,Mn2), concat_int(S1,S2)},
  Date = {concat_int(Y1,Y2,Y3,Y4), concat_int(M1,M2), concat_int(D1,D2)},
  {ok, {Date, Time}, Rest};
parse_date(<<Y1,Y2,Y3,Y4,$-,M1,M2,$-,D1,D2,$T,H1,H2,$:,Mn1,Mn2,$:,S1,S2,$.,_MS1,$-,_Tz1,_Tz2,$:,_Tz3,_Tz4," ",Rest/binary>>)->
  Time = {concat_int(H1,H2), concat_int(Mn1,Mn2), concat_int(S1,S2)},
  Date = {concat_int(Y1,Y2,Y3,Y4), concat_int(M1,M2), concat_int(D1,D2)},
  {ok, {Date, Time}, Rest};
parse_date(<<Y1,Y2,Y3,Y4,$-,M1,M2,$-,D1,D2,$T,H1,H2,$:,Mn1,Mn2,$:,S1,S2,$.,_MS1,_MS2,$-,_Tz1,_Tz2,$:,_Tz3,_Tz4," ",Rest/binary>>)->
  Time = {concat_int(H1,H2), concat_int(Mn1,Mn2), concat_int(S1,S2)},
  Date = {concat_int(Y1,Y2,Y3,Y4), concat_int(M1,M2), concat_int(D1,D2)},
  {ok, {Date, Time}, Rest};
parse_date(<<Y1,Y2,Y3,Y4,$-,M1,M2,$-,D1,D2,$T,H1,H2,$:,Mn1,Mn2,$:,S1,S2,$.,_MS1,_MS2,_MS3,$-,_Tz1,_Tz2,$:,_Tz3,_Tz4," ",Rest/binary>>)->
  Time = {concat_int(H1,H2), concat_int(Mn1,Mn2), concat_int(S1,S2)},
  Date = {concat_int(Y1,Y2,Y3,Y4), concat_int(M1,M2), concat_int(D1,D2)},
  {ok, {Date, Time}, Rest};
parse_date(<<Y1,Y2,Y3,Y4,$-,M1,M2,$-,D1,D2,$T,H1,H2,$:,Mn1,Mn2,$:,S1,S2,$.,_MS1,_MS2,_MS3,_MS4,$-,_Tz1,_Tz2,$:,_Tz3,_Tz4," ",Rest/binary>>)->
  Time = {concat_int(H1,H2), concat_int(Mn1,Mn2), concat_int(S1,S2)},
  Date = {concat_int(Y1,Y2,Y3,Y4), concat_int(M1,M2), concat_int(D1,D2)},
  {ok, {Date, Time}, Rest};
parse_date(<<Y1,Y2,Y3,Y4,$-,M1,M2,$-,D1,D2,$T,H1,H2,$:,Mn1,Mn2,$:,S1,S2,$.,_MS1,_MS2,_MS3,_MS4,_MS5,$-,_Tz1,_Tz2,$:,_Tz3,_Tz4," ",Rest/binary>>)->
  Time = {concat_int(H1,H2), concat_int(Mn1,Mn2), concat_int(S1,S2)},
  Date = {concat_int(Y1,Y2,Y3,Y4), concat_int(M1,M2), concat_int(D1,D2)},
  {ok, {Date, Time}, Rest};
parse_date(<<Y1,Y2,Y3,Y4,$-,M1,M2,$-,D1,D2,$T,H1,H2,$:,Mn1,Mn2,$:,S1,S2,$.,_MS1,_MS2,_MS3,_MS4,_MS5,_MS6,$-,_Tz1,_Tz2,$:,_Tz3,_Tz4," ",Rest/binary>>)->
  Time = {concat_int(H1,H2), concat_int(Mn1,Mn2), concat_int(S1,S2)},
  Date = {concat_int(Y1,Y2,Y3,Y4), concat_int(M1,M2), concat_int(D1,D2)},
  {ok, {Date, Time}, Rest};
parse_date(<<Y1,Y2,Y3,Y4,$-,M1,M2,$-,D1,D2,$T,H1,H2,$:,Mn1,Mn2,$:,S1,S2,$.,_MS1,_MS2,_MS3,_MS4,_MS5,_MS6,_MS7,$-,_Tz1,_Tz2,$:,_Tz3,_Tz4," ",Rest/binary>>)->
  Time = {concat_int(H1,H2), concat_int(Mn1,Mn2), concat_int(S1,S2)},
  Date = {concat_int(Y1,Y2,Y3,Y4), concat_int(M1,M2), concat_int(D1,D2)},
  {ok, {Date, Time}, Rest};
parse_date(<<Y1,Y2,Y3,Y4,$-,M1,M2,$-,D1,D2,$T,H1,H2,$:,Mn1,Mn2,$:,S1,S2,$.,_MS1,_MS2,_MS3,_MS4,_MS5,_MS6,_MS7,_MS8,$-,_Tz1,_Tz2,$:,_Tz3,_Tz4," ",Rest/binary>>)->
  Time = {concat_int(H1,H2), concat_int(Mn1,Mn2), concat_int(S1,S2)},
  Date = {concat_int(Y1,Y2,Y3,Y4), concat_int(M1,M2), concat_int(D1,D2)},
  {ok, {Date, Time}, Rest};

% Z
parse_date(<<Y1,Y2,Y3,Y4,$-,M1,M2,$-,D1,D2,$T,H1,H2,$:,Mn1,Mn2,$:,S1,S2,$.,_MS1,$Z," ",Rest/binary>>)->
  Time = {concat_int(H1,H2), concat_int(Mn1,Mn2), concat_int(S1,S2)},
  Date = {concat_int(Y1,Y2,Y3,Y4), concat_int(M1,M2), concat_int(D1,D2)},
  {ok, {Date, Time}, Rest};
parse_date(<<Y1,Y2,Y3,Y4,$-,M1,M2,$-,D1,D2,$T,H1,H2,$:,Mn1,Mn2,$:,S1,S2,$.,_MS1,_MS2,$Z," ",Rest/binary>>)->
  Time = {concat_int(H1,H2), concat_int(Mn1,Mn2), concat_int(S1,S2)},
  Date = {concat_int(Y1,Y2,Y3,Y4), concat_int(M1,M2), concat_int(D1,D2)},
  {ok, {Date, Time}, Rest};
parse_date(<<Y1,Y2,Y3,Y4,$-,M1,M2,$-,D1,D2,$T,H1,H2,$:,Mn1,Mn2,$:,S1,S2,$.,_MS1,_MS2,_MS3,$Z," ",Rest/binary>>)->
  Time = {concat_int(H1,H2), concat_int(Mn1,Mn2), concat_int(S1,S2)},
  Date = {concat_int(Y1,Y2,Y3,Y4), concat_int(M1,M2), concat_int(D1,D2)},
  {ok, {Date, Time}, Rest};
parse_date(<<Y1,Y2,Y3,Y4,$-,M1,M2,$-,D1,D2,$T,H1,H2,$:,Mn1,Mn2,$:,S1,S2,$.,_MS1,_MS2,_MS3,_MS4,$Z," ",Rest/binary>>)->
  Time = {concat_int(H1,H2), concat_int(Mn1,Mn2), concat_int(S1,S2)},
  Date = {concat_int(Y1,Y2,Y3,Y4), concat_int(M1,M2), concat_int(D1,D2)},
  {ok, {Date, Time}, Rest};
parse_date(<<Y1,Y2,Y3,Y4,$-,M1,M2,$-,D1,D2,$T,H1,H2,$:,Mn1,Mn2,$:,S1,S2,$.,_MS1,_MS2,_MS3,_MS4,_MS5,$Z," ",Rest/binary>>)->
  Time = {concat_int(H1,H2), concat_int(Mn1,Mn2), concat_int(S1,S2)},
  Date = {concat_int(Y1,Y2,Y3,Y4), concat_int(M1,M2), concat_int(D1,D2)},
  {ok, {Date, Time}, Rest};
parse_date(<<Y1,Y2,Y3,Y4,$-,M1,M2,$-,D1,D2,$T,H1,H2,$:,Mn1,Mn2,$:,S1,S2,$.,_MS1,_MS2,_MS3,_MS4,_MS5,_MS6,$Z," ",Rest/binary>>)->
  Time = {concat_int(H1,H2), concat_int(Mn1,Mn2), concat_int(S1,S2)},
  Date = {concat_int(Y1,Y2,Y3,Y4), concat_int(M1,M2), concat_int(D1,D2)},
  {ok, {Date, Time}, Rest};
parse_date(<<Y1,Y2,Y3,Y4,$-,M1,M2,$-,D1,D2,$T,H1,H2,$:,Mn1,Mn2,$:,S1,S2,$.,_MS1,_MS2,_MS3,_MS4,_MS5,_MS6,_MS7,$Z," ",Rest/binary>>)->
  Time = {concat_int(H1,H2), concat_int(Mn1,Mn2), concat_int(S1,S2)},
  Date = {concat_int(Y1,Y2,Y3,Y4), concat_int(M1,M2), concat_int(D1,D2)},
  {ok, {Date, Time}, Rest};
parse_date(<<Y1,Y2,Y3,Y4,$-,M1,M2,$-,D1,D2,$T,H1,H2,$:,Mn1,Mn2,$:,S1,S2,$.,_MS1,_MS2,_MS3,_MS4,_MS5,_MS6,_MS7,_MS8,$Z," ",Rest/binary>>)->
  Time = {concat_int(H1,H2), concat_int(Mn1,Mn2), concat_int(S1,S2)},
  Date = {concat_int(Y1,Y2,Y3,Y4), concat_int(M1,M2), concat_int(D1,D2)},
  {ok, {Date, Time}, Rest};

parse_date(<<_,Rest/binary>>)->
  parse_date(Rest).

%% @doc hostname pattern
%% @example d.de02fad5-ca75-4863-8d0a-de58404f9225
-spec parse_hostname(binary()) -> {ok, binary(), binary()} | error.
parse_hostname(<<" ",Rest/binary>>)->
  {ok, undefined, Rest};
parse_hostname(<<Hostname:1/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:2/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:3/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:4/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:5/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:6/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:7/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:8/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:9/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:10/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:11/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:12/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:13/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:14/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:15/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:16/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:17/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:18/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:19/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:20/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:21/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:22/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:23/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:24/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:25/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:26/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:27/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:28/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:29/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:30/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:31/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:32/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:33/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:34/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:35/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:36/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:37/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:38/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:39/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:40/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:41/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:42/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:43/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:44/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:45/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:46/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:47/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:48/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:49/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:50/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:51/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:52/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:53/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:54/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:55/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:56/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:57/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:58/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:59/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:60/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:61/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:62/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:63/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:64/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:65/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:66/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:67/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:68/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:69/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:70/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:71/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:72/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:73/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:74/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:75/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:76/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:77/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:78/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:79/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:80/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:81/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:82/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:83/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:84/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:85/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:86/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:87/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:88/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:89/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:90/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:91/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:92/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:93/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:94/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:95/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:96/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:97/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:98/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:99/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:100/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:101/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:102/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:103/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:104/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:105/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:106/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:107/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:108/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:109/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:110/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:111/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:112/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:113/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:114/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:115/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:116/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:117/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:118/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:119/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:120/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:121/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:122/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:123/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:124/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:125/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:126/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:127/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:128/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:129/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:130/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:131/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:132/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:133/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:134/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:135/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:136/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:137/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:138/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:139/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:140/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:141/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:142/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:143/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:144/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:145/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:146/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:147/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:148/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:149/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:150/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:151/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:152/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:153/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:154/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:155/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:156/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:157/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:158/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:159/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:160/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:161/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:162/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:163/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:164/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:165/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:166/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:167/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:168/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:169/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:170/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:171/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:172/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:173/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:174/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:175/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:176/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:177/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:178/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:179/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:180/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:181/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:182/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:183/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:184/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:185/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:186/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:187/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:188/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:189/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:190/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:191/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:192/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:193/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:194/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:195/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:196/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:197/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:198/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:199/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:200/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:201/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:202/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:203/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:204/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:205/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:206/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:207/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:208/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:209/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:210/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:211/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:212/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:213/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:214/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:215/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:216/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:217/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:218/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:219/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:220/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:221/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:222/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:223/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:224/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:225/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:226/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:227/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:228/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:229/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:230/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:231/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:232/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:233/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:234/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:235/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:236/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:237/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:238/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:239/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:240/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:241/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:242/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:243/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:244/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:245/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:246/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:247/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:248/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:249/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:250/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:251/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:252/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:253/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:254/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(<<Hostname:255/binary," ",Rest/binary>>)->
  {ok, Hostname, Rest};
parse_hostname(_)->
  error.

parse_app_name(<<" ",Rest/binary>>)->
  {ok, undefined, Rest};
parse_app_name(<<AppName:1/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:2/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:3/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:4/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:5/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:6/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:7/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:8/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:9/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:10/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:11/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:12/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:13/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:14/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:15/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:16/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:17/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:18/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:19/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:20/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:21/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:22/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:23/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:24/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:25/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:26/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:27/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:28/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:29/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:30/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:31/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:32/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:33/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:34/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:35/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:36/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:37/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:38/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:39/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:40/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:41/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:42/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:43/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:44/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:45/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:46/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:47/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(<<AppName:48/binary," ",Rest/binary>>)->
  {ok, AppName, Rest};
parse_app_name(_)->
  error.

parse_proc_id(<<" ",Rest/binary>>)->
  {ok, undefined, Rest};
parse_proc_id(<<ProcID:1/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:2/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:3/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:4/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:5/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:6/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:7/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:8/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:9/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:10/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:11/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:12/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:13/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:14/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:15/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:16/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:17/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:18/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:19/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:20/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:21/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:22/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:23/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:24/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:25/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:26/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:27/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:28/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:29/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:30/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:31/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:32/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:33/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:34/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:35/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:36/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:37/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:38/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:39/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:40/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:41/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:42/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:43/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:44/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:45/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:46/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:47/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:48/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:49/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:50/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:51/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:52/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:53/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:54/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:55/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:56/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:57/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:58/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:59/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:60/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:61/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:62/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:63/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:64/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:65/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:66/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:67/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:68/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:69/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:70/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:71/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:72/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:73/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:74/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:75/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:76/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:77/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:78/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:79/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:80/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:81/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:82/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:83/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:84/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:85/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:86/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:87/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:88/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:89/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:90/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:91/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:92/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:93/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:94/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:95/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:96/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:97/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:98/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:99/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:100/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:101/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:102/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:103/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:104/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:105/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:106/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:107/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:108/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:109/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:110/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:111/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:112/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:113/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:114/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:115/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:116/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:117/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:118/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:119/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:120/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:121/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:122/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:123/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:124/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:125/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:126/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:127/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(<<ProcID:128/binary," ",Rest/binary>>)->
  {ok, ProcID, Rest};
parse_proc_id(_)->
  error.

%% This is pretty messy... :/ - we get about 10,000 message/sec more with it
parse_message_id(<<"- - ",Message/binary>>)->
  {ok, undefined, Message};
parse_message_id(<<"- ",MessageID:1/binary," - ",Message/binary>>)->
  {ok, MessageID, Message};
parse_message_id(<<"- ",MessageID:2/binary," - ",Message/binary>>)->
  {ok, MessageID, Message};
parse_message_id(<<"- ",MessageID:3/binary," - ",Message/binary>>)->
  {ok, MessageID, Message};
parse_message_id(<<"- ",MessageID:4/binary," - ",Message/binary>>)->
  {ok, MessageID, Message};
parse_message_id(<<"- ",MessageID:5/binary," - ",Message/binary>>)->
  {ok, MessageID, Message};
parse_message_id(<<"- ",MessageID:6/binary," - ",Message/binary>>)->
  {ok, MessageID, Message};
parse_message_id(<<"- ",MessageID:7/binary," - ",Message/binary>>)->
  {ok, MessageID, Message};
parse_message_id(<<"- ",MessageID:8/binary," - ",Message/binary>>)->
  {ok, MessageID, Message};
parse_message_id(<<"- ",MessageID:9/binary," - ",Message/binary>>)->
  {ok, MessageID, Message};
parse_message_id(<<"- ",MessageID:10/binary," - ",Message/binary>>)->
  {ok, MessageID, Message};
parse_message_id(<<"- ",MessageID:11/binary," - ",Message/binary>>)->
  {ok, MessageID, Message};
parse_message_id(<<"- ",MessageID:12/binary," - ",Message/binary>>)->
  {ok, MessageID, Message};
parse_message_id(<<"- ",MessageID:13/binary," - ",Message/binary>>)->
  {ok, MessageID, Message};
parse_message_id(<<"- ",MessageID:14/binary," - ",Message/binary>>)->
  {ok, MessageID, Message};
parse_message_id(<<"- ",MessageID:15/binary," - ",Message/binary>>)->
  {ok, MessageID, Message};
parse_message_id(<<"- ",MessageID:16/binary," - ",Message/binary>>)->
  {ok, MessageID, Message};
parse_message_id(<<"- ",MessageID:17/binary," - ",Message/binary>>)->
  {ok, MessageID, Message};
parse_message_id(<<"- ",MessageID:18/binary," - ",Message/binary>>)->
  {ok, MessageID, Message};
parse_message_id(<<"- ",MessageID:19/binary," - ",Message/binary>>)->
  {ok, MessageID, Message};
parse_message_id(<<"- ",MessageID:21/binary," - ",Message/binary>>)->
  {ok, MessageID, Message};
parse_message_id(<<"- ",MessageID:22/binary," - ",Message/binary>>)->
  {ok, MessageID, Message};
parse_message_id(<<"- ",MessageID:23/binary," - ",Message/binary>>)->
  {ok, MessageID, Message};
parse_message_id(<<"- ",MessageID:24/binary," - ",Message/binary>>)->
  {ok, MessageID, Message};
parse_message_id(<<"- ",MessageID:25/binary," - ",Message/binary>>)->
  {ok, MessageID, Message};
parse_message_id(<<"- ",MessageID:26/binary," - ",Message/binary>>)->
  {ok, MessageID, Message};
parse_message_id(<<"- ",MessageID:27/binary," - ",Message/binary>>)->
  {ok, MessageID, Message};
parse_message_id(<<"- ",MessageID:28/binary," - ",Message/binary>>)->
  {ok, MessageID, Message};
parse_message_id(<<"- ",MessageID:29/binary," - ",Message/binary>>)->
  {ok, MessageID, Message};
parse_message_id(<<"- ",MessageID:31/binary," - ",Message/binary>>)->
  {ok, MessageID, Message};
parse_message_id(<<"- ",MessageID:32/binary," - ",Message/binary>>)->
  {ok, MessageID, Message};
parse_message_id(<<"- ",Message/binary>>)->
  {ok, undefined, Message};
parse_message_id(_)->
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
