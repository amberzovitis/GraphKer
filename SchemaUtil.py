from fileType import FileType
from Util import Util

class SchemaUtil:

    def __init__(self, driver):
        self.driver = driver

    # Clear Database
    def clear(self):
        # Clear Database from existing nodes and relationships
        query = """CALL apoc.periodic.iterate('MATCH (n) RETURN n', 'DETACH DELETE n', {batchSize:2000})"""
        session = self.driver.session()
        session.run(query)
        print("\nPrevious Data have been deleted.")

        self.clearSchema()
        print("\nDatabase is clear and ready for imports.")

    # Clear Schema
    def clearSchema(self):
        # Clear Database from existing constraints and indexes
        query = """CALL apoc.schema.assert({}, {}, true)"""
        session = self.driver.session()
        session.run(query)
        print("\nPrevious Schema has been deleted.")

    # Constraints and Indexes
    def schema_script(self):
        # Create Constraints and Indexes
        query = """CALL apoc.cypher.runSchemaFile("ConstraintsIndexes.cypher")"""
        session = self.driver.session()
        session.run(query)
        print("\nSchema with Constraints and Indexes insertion completed.")