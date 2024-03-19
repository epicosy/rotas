from graphene import ObjectType
from rotas.objects.graphene.mutations.create.data import AddDatasetVulnerabilities, CreateDataset, CreateProfile
from rotas.objects.graphene.mutations.delete.data import RemoveDataset, RemoveDatasetVulnerabilities
from rotas.objects.graphene.mutations.update.data import EditDataset
from rotas.objects.graphene.mutations.update.git import EditRepositorySoftwareType


# TODO: this has functionality that is not part of this project yet

"""
class LoadFile(graphene.Mutation):
    class Arguments:
        id = graphene.String(required=True)

    file = graphene.Field(lambda: CommitFile)

    def mutate(self, info, id: str):
    
        file = CommitFile.get_query(info).filter_by(id=id).first()

        if not file:
            raise GraphQLError(f"File with id {id} does not exist")

        try:
            content = get_file_content_from_url(file.raw_url)
        except Exception as e:
            raise GraphQLError(f"Error loading file content from url {file.raw_url}: {e}")

        lines = Line.get_query(info).filter_by(commit_file_id=file.id).all()

        if not lines:
            line_records = []

            for i, line in enumerate(content.split("\n"), 1):
                line_id = get_digest(f"{file.id}-{i}")
                line_records.append(LineModel(id=line_id, number=i, content=line, commit_file_id=file.id))

            LineModel.add_all(line_records)

        return LoadFile(file=file)
"""

# TODO: this has functionality that is not part of this project
"""
class ExtractFunctions(graphene.Mutation):
    class Arguments:
        id = graphene.String(required=True)

    file = graphene.Field(lambda: CommitFile)

    def mutate(self, info, id: str):
        file = CommitFile.get_query(info).filter_by(id=id).first()

        if not file:
            raise GraphQLError(f"File with id {id} does not exist")

        if file.extension != ".java":
            raise GraphQLError(f"File with id {id} is not within available languages: [Java]")

        functions = Function.get_query(info).filter_by(commit_file_id=file.id).order_by(FunctionModel.start).all()

        if not functions:

            lines = Line.get_query(info).filter_by(commit_file_id=file.id).all()

            if not lines:
                raise GraphQLError(f"File with id {id} has not been previously loaded")

            try:
                jve = JavaMethodExtractor(code_lines=[l.content for l in lines])
            except Exception as e:
                raise GraphQLError(f"Failed to extract methods: {str(e)}")

            for method in jve.methods:
                functions.append(FunctionModel(id=get_digest(f"{file.id}-{method.name}-{method.start_line}"),
                                               name=method.name, start_line=method.start_line, start_col=method.start_col,
                                               end_line=method.end_line, end_col=method.end_col, commit_file_id=file.id,
                                               size=len(method))
                                 )

            FunctionModel.add_all(functions)

        return ExtractFunctions(file=file)
"""


class Mutation(ObjectType):
    create_dataset = CreateDataset.Field()
    create_profile = CreateProfile.Field()
    remove_dataset = RemoveDataset.Field()
    remove_dataset_vulnerabilities = RemoveDatasetVulnerabilities.Field()
    add_vulnerabilities_to_dataset = AddDatasetVulnerabilities.Field()
    edit_dataset = EditDataset.Field()
    repository_software_type = EditRepositorySoftwareType.Field()
    # load_file = LoadFile.Field()
