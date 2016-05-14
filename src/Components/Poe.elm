module Components.Poe exposing (..)

import Html exposing (..)
import Html.Attributes exposing (..)

import MyMod.HaskellLike exposing (..)

poeComponent : Html msg
poeComponent = h1 [ style [("color", "#fff")] ] [text "I am a poe."]

script : List (Attribute msg) -> List (Html msg) -> Html msg
script = node "script"

link : List (Attribute msg) -> List (Html msg) -> Html msg
link = node "link"

bootstrapLink : Html msg
bootstrapLink = link [Html.Attributes.href ""] []
