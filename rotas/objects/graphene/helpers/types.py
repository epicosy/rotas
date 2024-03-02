import graphene
from graphene import ObjectType


class GrapheneCount(graphene.ObjectType):
    key = graphene.String()
    value = graphene.Int()


class NestedGrapheneCount(ObjectType):
    key = graphene.String()
    values = graphene.List(GrapheneCount)


class ProfileCount(ObjectType):
    total = graphene.Int()
    year = graphene.List(lambda: GrapheneCount)
    cwe = graphene.List(lambda: GrapheneCount)
    score = graphene.List(lambda: GrapheneCount)
    changes = graphene.List(lambda: GrapheneCount)
    files = graphene.List(lambda: GrapheneCount)
    extensions = graphene.List(lambda: GrapheneCount)


class Position(ObjectType):
    line = graphene.Int()
    column = graphene.Int()


# TODO: to be added
# class MethodBoundary(ObjectType):
#    name = graphene.String()
#    start = graphene.Field(lambda: Position)
#    end = graphene.Field(lambda: Position)
#    code = graphene.List(graphene.String)


class Stats(ObjectType):
    total = graphene.Int()
    labeled = graphene.Int()
    references = graphene.Int()
    commits = graphene.Int()


class LinkCount(ObjectType):
    at = graphene.String()
    to = graphene.String()
    count = graphene.Int()
