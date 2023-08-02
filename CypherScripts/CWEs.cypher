// Insert CWEs Catalog - Cypher Script

// Insert External References for CWEs
UNWIND [filesToImport] AS files
CALL apoc.load.json(files) YIELD value

FOREACH (reference IN value.Weakness_Catalog.External_References.External_Reference |
  MERGE (r:External_Reference_CWE {Reference_ID: reference.Reference_ID})
  SET r.Author = [value IN reference.Author | value], r.Title = reference.Title,
  r.Edition = reference.Edition, r.URL = reference.URL,
  r.Publication_Year = reference.Publication_Year, r.Publisher = reference.Publisher
);

// ------------------------------------------------------------------------
// Insert Weaknesses for CWEs
UNWIND [filesToImport] AS files
CALL apoc.load.json(files) YIELD value
UNWIND value.Weakness_Catalog.Weaknesses.Weakness AS weakness

// General Info for CWEs Dataset
MERGE (i:General_Info_CWE {
  Name: value.Weakness_Catalog.Name, Version: value.Weakness_Catalog.Version,
  Date: value.Weakness_Catalog.Date, Schema: 'https://cwe.mitre.org/data/xsd/cwe_schema_v6.4.xsd'
})

// Insert CWEs
MERGE (w:CWE {
  Name: 'CWE-' + weakness.ID
})
SET w.Extended_Name = weakness.Name, w.Abstraction = weakness.Abstraction,
w.Structure = weakness.Structure, w.Status = weakness.Status, w.Description = weakness.Description,
w.Extended_Description = apoc.convert.toString(weakness.Extended_Description),
w.Likelihood_Of_Exploit = weakness.Likelihood_Of_Exploit,
w.Background_Details = apoc.convert.toString(weakness.Background_Details.Background_Detail),
w.Modes_Of_Introduction = [value IN weakness.Modes_Of_Introduction.Introduction | value.Phase],
w.Submission_Date = weakness.Content_History.Submission.Submission_Date,
w.Submission_Name = weakness.Content_History.Submission.Submission_Name,
w.Submission_Organization = weakness.Content_History.Submission.Submission_Organization,
w.Modifications = [value IN weakness.Content_History.Modification | apoc.convert.toString(value)],
w.Alternate_Terms = apoc.convert.toString(weakness.Alternate_Terms),
w.Notes = [value IN weakness.Notes.Note | apoc.convert.toString(value)],
w.Affected_Resources = [value IN weakness.Affected_Resources.Affected_Resource | value],
w.Functional_Areas = [value IN weakness.Functional_Areas.Functional_Area | value]
MERGE (w)-[:belongsTo]->(i)

// Insert Related Weaknesses CWE --> CWE
WITH w, weakness
UNWIND weakness.Related_Weaknesses.Related_Weakness AS Rel_Weakness
MATCH (cwe:CWE)
  WHERE cwe.Name = 'CWE-' + Rel_Weakness.CWE_ID
MERGE (w)-[:Related_Weakness {Nature: Rel_Weakness.Nature}]->(cwe)

// Insert Applicable Platforms for CWEs
WITH w, weakness
UNWIND weakness.Applicable_Platforms AS appPl
FOREACH (lg IN appPl.Language |
  MERGE (ap:Applicable_Platform {Type: 'Language', Prevalence: lg.Prevalence,
                                 Name: coalesce(lg.Name, ' NOT SET '), Class: coalesce(lg.Class, ' NOT SET ')})
  MERGE (w)-[:Applicable_Platform]->(ap)
)

WITH w, weakness, appPl
FOREACH (tch IN appPl.Technology |
  MERGE (ap:Applicable_Platform {Type: 'Technology', Prevalence: tch.Prevalence,
                                 Name: coalesce(tch.Name, ' NOT SET '), Class: coalesce(tch.Class, ' NOT SET ')})
  MERGE (w)-[:Applicable_Platform]->(ap)
)

WITH w, weakness, appPl
FOREACH (arc IN appPl.Architecture |
  MERGE (ap:Applicable_Platform {Type: 'Architecture', Prevalence: arc.Prevalence,
                                 Name: coalesce(arc.Name, ' NOT SET '), Class: coalesce(arc.Class, ' NOT SET ')})
  MERGE (w)-[:Applicable_Platform]->(ap)
)

WITH w, weakness, appPl
FOREACH (os IN appPl.Operating_System |
  MERGE (ap:Applicable_Platform {Type: 'Operating System', Prevalence: os.Prevalence,
                                 Name: coalesce(os.Name, ' NOT SET '), Class: coalesce(os.Class, ' NOT SET ')})
  MERGE (w)-[:Applicable_Platform]->(ap)
)

// Insert Demonstrative Examples for CWEs
WITH w, weakness
FOREACH (example IN weakness.Demonstrative_Examples.Demonstrative_Example |
  MERGE (ex:Demonstrative_Example {
    Intro_Text: apoc.convert.toString(example.Intro_Text)
  })
  MERGE (w)-[r:hasExample]->(ex)
  SET r.Body_Text = [value IN example.Body_Text | apoc.convert.toString(value)],
  r.Example_Code = [value IN example.Example_Code | apoc.convert.toString(value)]
)

// Insert Consequences for CWEs
WITH w, weakness
FOREACH (consequence IN weakness.Common_Consequences.Consequence |
  MERGE (con:Consequence {Scope: [value IN consequence.Scope | value]})
  MERGE (w)-[rel:hasConsequence]->(con)
  SET rel.Impact = [value IN consequence.Impact | value],
  rel.Note = consequence.Note, rel.Likelihood = consequence.Likelihood
)

// Insert Detection Methods for CWEs
WITH w, weakness
FOREACH (dec IN weakness.Detection_Methods.Detection_Method |
  MERGE (d:Detection_Method {
    Method: dec.Method
  })
  MERGE (w)-[wd:canBeDetected {Description: apoc.convert.toString(dec.Description)}]->(d)
  SET wd.Effectiveness = dec.Effectiveness, wd.Effectiveness_Notes = dec.Effectiveness_Notes,
  wd.Detection_Method_ID = dec.Detection_Method_ID
)

// Insert Potential Mitigations for CWEs
WITH w, weakness
FOREACH (mit IN weakness.Potential_Mitigations.Mitigation |
  MERGE (m:Mitigation {
    Description: apoc.convert.toString(mit.Description)
  })
  SET m.Phase = [value IN mit.Phase | value], m.Strategy = mit.Strategy,
  m.Effectiveness = mit.Effectiveness, m.Effectiveness_Notes = mit.Effectiveness_Notes,
  m.Mitigation_ID = mit.Mitigation_ID
  MERGE (w)-[:hasMitigation]->(m)
)

// Insert Related Attack Patterns - CAPEC for CWEs
WITH w, weakness
FOREACH (rap IN weakness.Related_Attack_Patterns.Related_Attack_Pattern |
  MERGE (cp:CAPEC {
    Name: 'CAPEC-' + rap.CAPEC_ID
  })
  MERGE (w)-[:RelatedAttackPattern]->(cp)
)

// Public References for CWEs
WITH w, weakness
UNWIND weakness.References.Reference AS exReference
MATCH (ref:External_Reference_CWE)
  WHERE ref.Reference_ID = exReference.External_Reference_ID
MERGE (w)-[:hasExternal_Reference]->(ref);

// ------------------------------------------------------------------------
// Insert Categories for CWEs
UNWIND [filesToImport] AS files
CALL apoc.load.json(files) YIELD value

UNWIND value.Weakness_Catalog.Categories.Category AS category
MERGE (c:CWE {
  Name: 'CWE-' + category.ID
})
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
OPTIONAL MATCH (MemberWeak:CWE {Name: 'CWE-' + members.CWE_ID})
MERGE (c)-[:hasMember {ViewID: members.View_ID}]->(MemberWeak);

// ------------------------------------------------------------------------
// Insert Public References for each Category
UNWIND [filesToImport] AS files
CALL apoc.load.json(files) YIELD value

UNWIND value.Weakness_Catalog.Categories.Category AS category
UNWIND (
CASE category.References.Reference WHEN [] THEN [ null ]
  ELSE category.References.Reference
  END) AS categoryExReference
MATCH (c:CWE)
  WHERE c.Name = 'CWE-' + category.ID
OPTIONAL MATCH (catRef:External_Reference_CWE {Reference_ID: categoryExReference.External_Reference_ID})
MERGE (c)-[:hasExternal_Reference]->(catRef);

// ------------------------------------------------------------------------
// Insert Views for CWEs
UNWIND [filesToImport] AS files
CALL apoc.load.json(files) YIELD value

// Views
UNWIND value.Weakness_Catalog.Views.View AS view
MERGE (v:CWE_VIEW {ViewID: view.ID})
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
OPTIONAL MATCH (MemberWeak:CWE {Name: 'CWE-' + members.CWE_ID})
MERGE (v)-[:hasMember]->(MemberWeak);

// ------------------------------------------------------------------------
// Insert Public References for each View
UNWIND [filesToImport] AS files
CALL apoc.load.json(files) YIELD value

UNWIND value.Weakness_Catalog.Views.View AS view
UNWIND (
CASE view.References.Reference WHEN [] THEN [ null ]
  ELSE view.References.Reference
  END) AS viewExReference
MATCH (v:CWE_VIEW)
  WHERE v.ViewID = view.ID
OPTIONAL MATCH (viewRef:External_Reference_CWE {Reference_ID: viewExReference.External_Reference_ID})
MERGE (v)-[:hasExternal_Reference]->(viewRef);