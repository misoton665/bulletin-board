module Components.View exposing (view)

import Html exposing (..)
import Html.Attributes exposing (..)
import Html.Events exposing ( onClick )

import MyMod.HaskellLike exposing (..)

import Components.Model exposing (Model(..))
import Components.Update exposing (Message(..))
import Components.Hello exposing (..)

-- VIEW
-- Examples of:
-- 1)  an externally defined component ('hello', takes 'model' as arg)
-- 2a) styling through CSS classes (external stylesheet)
-- 2b) styling using inline style attribute (two variants)
view : Model -> Html Message
view model =
  div
    [ class "mt-palette-accent", style styles.wrapper ]
    <| flat [
      [ hello model,
        p [ style [( "color", "#FFF")] ] [ text ( "Elm Webpack Starter" ) ],
        p [] [text "poe"]
      ],
      List.repeat 3 $ p [] [text "rep"],
      [
        button [ class "mt-button-sm", onClick Increment ] [ text "FTW!" ],
        img [ src "img/elm.jpg", style [( "display", "block"), ( "margin", "10px auto")] ] []
      ]
    ]

-- CSS STYLES
type alias Wrapper = List(String, String)

wrapper : Wrapper
wrapper = [ ( "padding-top", "10px" )
          , ( "padding-bottom", "20px" )
          , ( "text-align", "center" )
          ]

styles : {wrapper: Wrapper}
styles = {wrapper = wrapper}