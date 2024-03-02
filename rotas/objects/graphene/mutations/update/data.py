import graphene

from graphql import GraphQLError

from rotas.objects.sqlalchemy.data import Dataset


class EditDataset(graphene.Mutation):
    class Arguments:
        id = graphene.Int(required=True)
        name = graphene.String(required=False)
        description = graphene.String(required=False)

    dataset = graphene.Field(lambda: Dataset)

    def mutate(self, info, id: int, name: str, description: str):
        dataset = Dataset.get_query(info).filter_by(id=id).first()

        if not dataset:
            raise GraphQLError(f"Dataset with id {id} does not exist")

        if name and name != dataset.name:
            # check if name does not exist in the dataset table
            if Dataset.get_query(info).filter_by(name=name).first():
                raise GraphQLError(f"Dataset with name {name} already exists")

            # check the length of the dataset name is not more than 255 characters
            if len(name) > 255:
                raise GraphQLError(f"Dataset name cannot be more than 255 characters")

            dataset.name = name

        if description:
            # check if the length of the description is not more than 1000 characters
            if len(description) > 1000:
                raise GraphQLError(f"Dataset description cannot be more than 1000 characters")

            dataset.description = description

        dataset.save()

        return EditDataset(dataset=dataset)
