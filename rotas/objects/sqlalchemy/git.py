import graphene
from graphene_sqlalchemy import SQLAlchemyObjectType

from rotas.arepo.arepo.models.git import (CommitModel, CommitFileModel, RepositoryModel, RepositoryTopicModel,
                                          TopicModel, RepositoryProductTypeModel)

from rotas.objects.sqlalchemy.common.platform import ProductType
from rotas.objects.sqlalchemy.code import Line, LineModel


class RepositoryTopic(SQLAlchemyObjectType):
    class Meta:
        model = RepositoryTopicModel
        use_connection = True


class Topic(SQLAlchemyObjectType):
    class Meta:
        model = TopicModel
        use_connection = True

    name = graphene.String()

    def resolve_name(self, info):
        return self.name


class CommitFile(SQLAlchemyObjectType):
    class Meta:
        model = CommitFileModel
        use_connection = True

    id = graphene.String()
    filename = graphene.String()
    patch = graphene.String()
    content = graphene.String()

    def resolve_content(self, info):
        lines = Line.get_query(info).filter_by(commit_file_id=self.id).order_by(LineModel.number).all()
        return '\n'.join([line.content for line in lines])

    def resolve_patch(self, info):
        return self.patch

    def resolve_id(self, info):
        return self.id

    def resolve_filename(self, info):
        return self.filename


class Commit(SQLAlchemyObjectType):
    class Meta:
        model = CommitModel
        use_connection = True

    files = graphene.List(lambda: CommitFile)

    def resolve_files(self, info):
        return self.files


class RepositoryProductType(SQLAlchemyObjectType):
    class Meta:
        model = RepositoryProductTypeModel
        use_connection = True


class Repository(SQLAlchemyObjectType):
    class Meta:
        model = RepositoryModel
        use_connection = True

    id = graphene.String()
    commits = graphene.List(lambda: Commit)
    commits_count = graphene.Int()
    topics = graphene.List(graphene.String)
    software_type = graphene.String()
    vulnerability_count = graphene.Int()

    def resolve_id(self, info):
        return self.id

    def resolve_vulnerability_count(self, info):
        return len(set([c.vulnerability_id for c in self.commits]))

    def resolve_software_type(self, info):
        relationships = RepositoryProductType.get_query(info).filter_by(repository_id=self.id).first()

        if relationships:
            return ProductType.get_query(info).filter_by(id=relationships.product_type_id).first().name
        else:
            return None

    def resolve_topics(self, info):
        rep_topic_query = RepositoryTopic.get_query(info).filter(RepositoryTopicModel.repository_id == self.id)
        topic_ids = [t.topic_id for t in rep_topic_query.all()]
        return [t.name for t in Topic.get_query(info).filter(TopicModel.id.in_(topic_ids)).all()]

    def resolve_commits(self, info):
        return self.commits

    def resolve_commits_count(self, info):
        return len([c for c in self.commits if c.kind != "parent"])
