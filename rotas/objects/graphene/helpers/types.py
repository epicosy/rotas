from collections import namedtuple

import graphene


from graphene import ObjectType


class GrapheneCount(graphene.ObjectType):
    key = graphene.String()
    value = graphene.Int()


GrapheneCountValueObject = namedtuple("GrapheneCount", ["key", "value"])

class NestedGrapheneCount(ObjectType):
    key = graphene.String()
    values = graphene.List(GrapheneCount)


class ProfileCount(ObjectType):
    total = graphene.Int()
    classes = graphene.List(lambda: GrapheneCount)
    cwe = graphene.List(lambda: GrapheneCount)
    languages = graphene.List(lambda: GrapheneCount)
    patches = graphene.List(lambda: GrapheneCount)
    changes = graphene.List(lambda: GrapheneCount)
    files = graphene.List(lambda: GrapheneCount)
    extensions = graphene.List(lambda: GrapheneCount)
    diff_blocks = graphene.List(lambda: GrapheneCount)


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


StatsValueObject = namedtuple("Stats", ["total", "labeled", "references", "commits"])


class LinkCount(ObjectType):
    at = graphene.String()
    to = graphene.String()
    count = graphene.Int()


LinkCountValueObject = namedtuple("LinkCount", ["at", "to", "count"])
