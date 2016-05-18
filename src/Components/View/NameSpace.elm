module Components.View.NameSpace exposing (..)

import Html exposing (Html, text)

import Components.Update.Update as U exposing (Message(..))

titleStr : String
titleStr = "Lab Activity Box -> LAB"

title : Html U.Message
title = text titleStr
