module Components.Model.Model exposing (Model(..), initialModel)

import Components.Application.Comment exposing (Comment)

type Model = Model (List Comment)

initialModel : Model
initialModel = Model []