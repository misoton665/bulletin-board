module Components.View.NameSpace exposing (..)


import Html exposing (Html, text)
import Components.Update.Update as U exposing (Message(..))


titleStr : String
titleStr =
  "Bulletin Board"

title : Html U.Message
title =
  text titleStr
