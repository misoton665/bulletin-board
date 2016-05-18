module Components.View.Hello exposing (..)

import Html exposing (Html, div, text)
import Html.Attributes exposing (class)
import String

import Components.Model.Model as M

-- hello component
hello : M.Model -> Html a
hello (M.Model value) =
  div
    [ class "mt-h2" ]
    [ text ( "Hello, World" ++ ( String.repeat value <| "!" ) ) ]
