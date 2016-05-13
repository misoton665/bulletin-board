module Components.Hello exposing (..)

import MyMod.HaskellLike exposing (..)

import Html exposing (..)
import Html.Attributes exposing (..)
import String

-- hello component
hello : Int -> Html a
hello model =
  div
    [ class "mt-h2" ]
    [ text ( "Hello, World" ++ ( String.repeat model $ "!" ) ) ]
