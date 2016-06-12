module Components.Model.Model exposing
  ( Model
  , CommentField
  , initialModel
  , initialCommentField
  )


import Components.Application.Comment exposing (Comment)


type alias CommentField =
  { author: String
  , body: String
  }


type alias Model =
  { comments: List Comment
  , commentField: CommentField
  }


initialModel : Model
initialModel = {comments = initialComments, commentField = initialCommentField}

initialComments : List Comment
initialComments = []

initialCommentField : CommentField
initialCommentField = {author = "", body = ""}