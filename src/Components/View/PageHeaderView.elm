module Components.View.PageHeaderView exposing (..)

import Html exposing (Html, div, h1, text)
-- import Html.Attributes exposing (..)
-- import Html.Events exposing (..)

import Components.Model.Model as M exposing (Model)
import Components.Update.Update as U exposing (Message(..))

import Components.View.NameSpace as Name

pageHeader : M.Model -> Html U.Message
pageHeader model =
  div [] [
    h1 [] [Name.title]
  ]