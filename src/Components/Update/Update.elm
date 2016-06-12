module Components.Update.Update exposing (
  Message(..), update
  )

import Components.Application.Comment exposing (Comment)
import Components.Model.Model exposing (Model(..))

-- UPDATE
type Message = Submission Comment | NoMessage

update : Message -> Model -> Model
update message (Model x) =
  case message of
    NoMessage -> Model x
    Submission comment -> Model <| comment :: x