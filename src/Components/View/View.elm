module Components.View.View exposing (view)

import List as L

import Html exposing (Html, div, p, text, button, img)
import Html.Attributes exposing (class, style, src)
import Html.Events exposing ( onClick )

import Components.Model.Model as M exposing (Model(..))
import Components.Update.Update as U exposing (..)
import Components.View.PageHeaderView exposing (pageHeader)
import Components.View.Hello as Hello

-- VIEW
-- Examples of:
-- 1)  an externally defined component ('hello', takes 'model' as arg)
-- 2a) styling through CSS classes (external stylesheet)
-- 2b) styling using inline style attribute (two variants)
view : M.Model -> Html (U.Message)
view model =
  div
    [ class "mt-palette-accent", style styles.wrapper ]
    <| L.concat [
      [ pageHeader model,
        Hello.hello model,
        p [ style [( "color", "#FFF")] ] [ text ( "Elm Webpack Starter" ) ],
        p [] [text "poe"]
      ], 
      L.repeat 3 <| p [] [text "rep"],
      [
        button [ class "mt-button-sm", onClick U.NoMessage ] [ text "FTW!" ],
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
