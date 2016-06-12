module Components.Update.Update exposing (
  ViewParts(..), Message(..), update
  )

import Components.Model.Model as M exposing (Model, CommentField, initialCommentField)

type ViewParts = CommentField M.CommentField

-- UPDATE
type Message = Submission | ChangeView ViewParts | NoMessage

update : Message -> M.Model -> M.Model
update message model =
  case message of
    NoMessage -> model
    Submission -> {model | comments = model.commentField :: model.comments, commentField = changeAuthor M.initialCommentField model.commentField.author}
    ChangeView parts -> case parts of
      CommentField field -> {model | commentField = field}

changeAuthor : M.CommentField -> String -> M.CommentField
changeAuthor field author = {field| author = author}