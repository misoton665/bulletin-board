module Components.Hello exposing (..)

import Html exposing (..)
import Html.Attributes exposing (..)
import String

import Components.Model exposing (..)

-- hello component
hello : Model -> Html a
hello (Model value) =
  div
    [ class "mt-h2" ]
    [ text ( "Hello, World" ++ ( String.repeat value <| "!" ) ) ]
