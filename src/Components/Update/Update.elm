module Components.Update.Update exposing
  ( ViewParts(..)
  , Message(..)
  , update
  )


import Components.Model.Model as M exposing (Model, CommentField, initialCommentField)


type ViewParts
  = CommentField M.CommentField


type Message 
  = Submission
   |ChangeView ViewParts
   |NoMessage


update : Message -> M.Model -> M.Model
update message model =
  case message of
    NoMessage ->
      model

    Submission ->
      submission model model.commentField

    ChangeView parts ->
      case parts of
        CommentField field ->
          {model | commentField = field}


submission : M.Model -> M.CommentField -> M.Model
submission model field =
  if field.author == "" || field.body == "" then
    model
  else
    {model | comments = field :: model.comments, commentField = changeAuthor M.initialCommentField field.author}


changeAuthor : M.CommentField -> String -> M.CommentField
changeAuthor field author = {field| author = author}