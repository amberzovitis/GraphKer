// Insert CAPECs Catalog - Cypher Script

// Insert External References for CAPECs
UNWIND [filesToImport] AS files
CALL apoc.load.json(files) YIELD value

FOREACH (reference IN value.Attack_Pattern_Catalog.External_References.External_Reference |
  MERGE (r:External_Reference_CAPEC {Reference_ID: reference.Reference_ID})
  SET r.Author = [value IN reference.Author | value], r.Title = reference.Title,
  r.Edition = reference.Edition, r.URL = reference.URL,
  r.Publication_Year = reference.Publication_Year, r.Publisher = reference.Publisher
);

// ------------------------------------------------------------------------
// Insert CAPECs
UNWIND [filesToImport] AS files
CALL apoc.load.json(files) YIELD value
UNWIND value.Attack_Pattern_Catalog.Attack_Patterns.Attack_Pattern AS capec

// General Info for CAPECs Dataset
MERGE (i:GeneralInfo_CAPEC {
  Name: value.Attack_Pattern_Catalog.Name, Version: value.Attack_Pattern_Catalog.Version,
  Date: value.Attack_Pattern_Catalog.Date, Schema: 'http://capec.mitre.org/data/xsd/ap_schema_v3.4.xsd'
})

// Insert Attack Patterns for CAPECs
MERGE (cp:CAPEC {
  Name: 'CAPEC-' + capec.ID
})
SET cp.ExtendedName = capec.Name, cp.Abstraction = capec.Abstraction,
cp.Status = capec.Status, cp.Description = apoc.convert.toString(capec.Description),
cp.Likelihood_Of_Attack = capec.Likelihood_Of_Attack, cp.Typical_Severity = capec.Typical_Severity,
cp.Alternate_Terms = [value IN capec.Alternate_Terms.Alternate_Term | value.Term],
cp.Prerequisites = [value IN capec.Prerequisites.Prerequisite | apoc.convert.toString(value)],
cp.Skills_Required = [value IN capec.Skills_Required.Skill | value.Level],
cp.Skills_Required_Description = [value IN capec.Skills_Required.Skill | coalesce(apoc.convert.toString(value.
  text), ' NOT SET ')],
cp.Mitigations = [value IN capec.Mitigations.Mitigation | apoc.convert.toString(value)],
cp.Examples = [value IN capec.Example_Instances.Example | apoc.convert.toString(value)],
cp.Notes = [value IN capec.Notes.Note | apoc.convert.toString(value)],
cp.Submission_Date = capec.Content_History.Submission.Submission_Date,
cp.Submission_Name = capec.Content_History.Submission.Submission_Name,
cp.Submission_Organization = capec.Content_History.Submission.Submission_Organization,
cp.Modifications = [value IN capec.Content_History.Modification | apoc.convert.toString(value)],
cp.Resources_Required = [value IN capec.Resources_Required.Resource | apoc.convert.toString(value)],
cp.Indicators = [value IN capec.Indicators.Indicator | apoc.convert.toString(value)]
MERGE (cp)-[:belongsTo]->(i)

// Consequences
FOREACH (consequence IN capec.Consequences.Consequence |
  MERGE (con:Consequence {Scope: [value IN consequence.Scope | value]})
  MERGE (cp)-[rel:hasConsequence]->(con)
  SET rel.Impact = [value IN consequence.Impact | value],
  rel.Note = consequence.Note, rel.Likelihood = consequence.Likelihood
)

// Mitigations
FOREACH (mit IN capec.Mitigations.Mitigation |
  MERGE (m:Mitigation {
    Description: apoc.convert.toString(mit)
  })
  MERGE (cp)-[:hasMitigation]->(m)
)

// Related Attack Patterns
WITH cp, capec
UNWIND (
CASE capec.Related_Attack_Patterns.Related_Attack_Pattern WHEN [] THEN [ null ]
  ELSE capec.Related_Attack_Patterns.Related_Attack_Pattern
  END) AS Rel_AP
OPTIONAL MATCH (pec:CAPEC {
  Name: 'CAPEC-' + Rel_AP.CAPEC_ID
})
MERGE (cp)-[:RelatedAttackPattern {Nature: Rel_AP.Nature}]->(pec)

// Public References for CAPECs
WITH cp, capec
UNWIND (
CASE capec.References.Reference WHEN [] THEN [ null ]
  ELSE capec.References.Reference
  END) AS ExReference
OPTIONAL MATCH (Ref:External_Reference_CAPEC {Reference_ID: ExReference.External_Reference_ID})
MERGE (cp)-[rel:hasExternal_Reference {CAPEC_ID: cp.Name}]->(Ref)
SET rel.Section = ExReference.Section;

// ------------------------------------------------------------------------
// Insert Categories for CAPECs
UNWIND [filesToImport] AS files
CALL apoc.load.json(files) YIELD value

UNWIND value.Attack_Pattern_Catalog.Categories.Category AS category
MERGE (c:CAPEC {Name: 'CAPEC-' + category.ID})
SET c.Extended_Name = category.Name, c.Status = category.Status, c.Summary = apoc.convert.toString(category.Summary),
c.Notes = apoc.convert.toString(category.Notes), c.Submission_Name = category.Content_History.Submission.
  Submission_Name,
c.Submission_Date = category.Content_History.Submission.Submission_Date,
c.Submission_Organization = category.Content_History.Submission.Submission_Organization,
c.Modification = [value IN category.Content_History.Modification | apoc.convert.toString(value)]

// Insert Members for each Category
WITH c, category
UNWIND (
CASE category.Relationships.Has_Member WHEN [] THEN [ null ]
  ELSE category.Relationships.Has_Member
  END) AS members
OPTIONAL MATCH (MemberAP:CAPEC {Name: 'CAPEC-' + members.CAPEC_ID})
MERGE (c)-[:hasMember]->(MemberAP);

// ------------------------------------------------------------------------
// Insert Public References for each Category
UNWIND [filesToImport] AS files
CALL apoc.load.json(files) YIELD value

UNWIND value.Attack_Pattern_Catalog.Categories.Category AS category
UNWIND (
CASE category.References.Reference WHEN [] THEN [ null ]
  ELSE category.References.Reference
  END) AS categoryExReference
MATCH (c:CAPEC)
  WHERE c.Name = 'CAPEC-' + category.ID
OPTIONAL MATCH (catRef:External_Reference_CAPEC {Reference_ID: categoryExReference.External_Reference_ID})
MERGE (c)-[rel:hasExternal_Reference]->(catRef)
SET rel.Section = categoryExReference.Section;

// ------------------------------------------------------------------------
// Insert Views for CAPECs
UNWIND [filesToImport] AS files
CALL apoc.load.json(files) YIELD value

// Views
UNWIND value.Attack_Pattern_Catalog.Views.View AS view
MERGE (v:CAPEC_VIEW {ViewID: view.ID})
SET v.Name = view.Name, v.Type = view.Type, v.Status = view.Status,
v.Objective = apoc.convert.toString(view.Objective), v.Filter = view.Filter,
v.Notes = apoc.convert.toString(view.Notes),
v.Submission_Name = view.Content_History.Submission.Submission_Name,
v.Submission_Date = view.Content_History.Submission.Submission_Date,
v.Submission_Organization = view.Content_History.Submission.Submission_Organization,
v.Modification = [value IN view.Content_History.Modification | apoc.convert.toString(value)]

// Insert Stakeholders for each View
FOREACH (value IN view.Audience.Stakeholder |
  MERGE (st:Stakeholder {Type: value.Type})
  MERGE (v)-[rel:usefulFor]->(st)
  SET rel.Description = value.Description
)

// Insert Members for each View
WITH v, view
UNWIND (
CASE view.Members.Has_Member WHEN [] THEN [ null ]
  ELSE view.Members.Has_Member
  END) AS members
OPTIONAL MATCH (MemberAP:CAPEC {Name: 'CAPEC-' + members.CAPEC_ID})
MERGE (v)-[:hasMember]->(MemberAP);

// ------------------------------------------------------------------------
// Insert Public References for each View
UNWIND [filesToImport] AS files
CALL apoc.load.json(files) YIELD value

UNWIND value.Attack_Pattern_Catalog.Views.View AS view
UNWIND (
CASE view.References.Reference WHEN [] THEN [ null ]
  ELSE view.References.Reference
  END) AS viewExReference
MATCH (v:CAPEC_VIEW)
  WHERE v.ViewID = view.ID
OPTIONAL MATCH (viewRef:External_Reference_CAPEC {Reference_ID: viewExReference.External_Reference_ID})
MERGE (v)-[:hasExternal_Reference]->(viewRef);