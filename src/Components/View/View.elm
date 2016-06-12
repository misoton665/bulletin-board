module Components.View.View exposing (view)

import List as L

import Html exposing (Html, div, p, text, button, img, input)
import Html.Attributes exposing (class, style, src, type', placeholder)
import Html.Events exposing ( onClick )

import Components.Application.Comment as Comment exposing (Comment)
import Components.Model.Model as M exposing (Model(..))
import Components.Update.Update as U exposing (..)
import Components.View.PageHeaderView exposing (pageHeader)

-- VIEW
-- Examples of:
-- 1)  an externally defined component ('hello', takes 'model' as arg)
-- 2a) styling through CSS classes (external stylesheet)
-- 2b) styling using inline style attribute (two variants)
view : M.Model -> Html (U.Message)
view (M.Model comments) =
  div
    [ class "mt-palette-accent", style styles.wrapper ]
    [
      pageHeader <| Model comments,
      commentField <| M.Model comments,
      button [ class "mt-button-sm", onClick <| U.Submission {author = "miso", body = "poe"} ] [ text "Submit!" ],
      Comment.toHtmlFromList comments
    ]

commentField : M.Model -> Html (U.Message)
commentField model = div [] [
    input [type' "text", placeholder "author"] [],
    input [type' "text", placeholder "comment"] []
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
