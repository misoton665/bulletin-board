module Components.View.View exposing (view)


import Html exposing (Html, div, p, text, button, img, input)
import Html.Attributes exposing (class, style, src, type', placeholder, value)
import Html.Events exposing ( onClick, onInput )
import Components.Application.Comment as Comment exposing (Comment)
import Components.Model.Model as M exposing (Model)
import Components.Update.Update as U exposing (..)
import Components.View.PageHeaderView exposing (pageHeader)


view : M.Model -> Html (U.Message)
view model =
  div
    [ class "mt-palette-accent", style styles.wrapper ]
    [
      pageHeader model,
      commentField model,
      button [ class "mt-button-sm", onClick U.Submission ] [ text "Submit!" ],
      Comment.toHtmlFromList model.comments
    ]


toComment : M.CommentField -> Comment.Comment
toComment cf =
  {author = cf.author, body = cf.body}


commentField : M.Model -> Html (U.Message)
commentField {commentField} =
  div [] [
    input [type' "text", placeholder "author", onInput <| editAuthor commentField] [],
    input [type' "text", placeholder "comment", value commentField.body, onInput <| editBody commentField] []
  ]


editAuthor : M.CommentField -> String -> U.Message
editAuthor commentField author =
  U.ChangeView <| U.CommentField {commentField | author = author}


editBody : M.CommentField -> String -> U.Message
editBody commentField body =
  U.ChangeView <| U.CommentField {commentField | body = body}


-- CSS STYLES
type alias Style =
  List(String, String)


wrapper : Style
wrapper = 
  [ ( "padding-top", "10px" )
  , ( "padding-bottom", "20px" )
  , ( "text-align", "center" )
  ]


styles : {wrapper: Style}
styles =
  {wrapper = wrapper}
