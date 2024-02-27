from graphene import Schema
from rotas.objects.graphene.query import Query
from rotas.objects.graphene.mutation import Mutation

schema = Schema(query=Query, mutation=Mutation)
