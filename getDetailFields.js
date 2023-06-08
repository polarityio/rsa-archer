const {
  flow,
  map,
  get,
  flatten,
  values,
  filter,
  find,
  eq,
  orderBy
} = require('lodash/fp');

const NodeCache = require('node-cache');
const applicationAndFieldDefinitionsCache = new NodeCache({
  stdTTL: 86400 // 1 Days
});
const parseErrorToReadableJson = (error) =>
  JSON.parse(JSON.stringify(error, Object.getOwnPropertyNames(error)));

const getDetailFields = async (
  { ContentId },
  options,
  authedAsyncRequestWithDefaults,
  callback,
  Logger
) => {
  try {
    const [allFields, fieldValues] = await Promise.all([
      getFieldDefinitions(options, authedAsyncRequestWithDefaults),
      getFieldValues(ContentId, options, authedAsyncRequestWithDefaults)
    ]);

    const detailFields = await getDetailFieldsWithNameAndType(
      fieldValues,
      allFields,
      options,
      authedAsyncRequestWithDefaults
    );

    callback(null, { detailFields });
  } catch (error) {
    const err = parseErrorToReadableJson(error);
    Logger.error(
      {
        detail: 'Failed Detail Fields Lookup',
        options,
        formattedError: err
      },
      'Detail Fields Lookup Failed'
    );
    return callback({
      errors: [
        {
          err: error,
          detail: error.message || 'Detail Fields Lookup Failed'
        }
      ]
    });
  }
};

const getFieldDefinitions = async (options, authedAsyncRequestWithDefaults) => {
  let allApplicationIds = applicationAndFieldDefinitionsCache.get('allApplicationIds');

  if (!allApplicationIds) {
    allApplicationIds = map(
      get('RequestedObject.Id'),
      await authedAsyncRequestWithDefaults({
        method: 'GET',
        url: `${options.host}/api/core/system/application/`,
        options
      })
    );
    applicationAndFieldDefinitionsCache.set('allApplicationIds', allApplicationIds);
  }

  let allFieldDefinitions =
    applicationAndFieldDefinitionsCache.get('allFieldDefinitions');

  if (!allFieldDefinitions) {
    allFieldDefinitions = flatten(
      await Promise.all(
        map(
          async (appId) =>
            map(
              get('RequestedObject'),
              await authedAsyncRequestWithDefaults({
                method: 'GET',
                url: `${options.host}/api/core/system/fielddefinition/application/${appId}`,
                options
              })
            ),
          allApplicationIds
        )
      )
    );
    applicationAndFieldDefinitionsCache.set('allFieldDefinitions', allFieldDefinitions);
  }
  return allFieldDefinitions;
};

const getFieldValues = async (ContentId, options, authedAsyncRequestWithDefaults) =>
  get(
    '0.RequestedObject.FieldContents',
    await authedAsyncRequestWithDefaults({
      method: 'POST',
      url: `${options.host}/api/core/content/fieldcontent`,
      body: {
        FieldIds: [],
        ContentIds: [ContentId]
      },
      options
    })
  );

const getDetailFieldsWithNameAndType = async (fieldValues, allFields) =>
  flow(
    values,
    filter(get('Value')),
    map((field) => ({
      ...field,
      Name: flow(find(flow(get('Id'), eq(field.FieldId))), get('Name'))(allFields),
      Type: get(field.Type, DISPLAY_FIELD_TYPES),
      TypeId: field.Type
    })),
    filter(get('Type')),
    orderBy('Name', 'asc')
  )(fieldValues);

const DISPLAY_FIELD_TYPES = {
  // 0: 'OTHER',
  1: 'TEXT',
  2: 'NUMERIC',
  3: 'DATE',
  // 4: 'VALUES_LIST',
  6: 'TRACKINGID',
  // 7: 'EXTERNAL_LINKS',
  // 8: 'USER_GROUP_LIST',
  // 9: 'CROSS_REFERENCE',
  // 11: 'ATTACHMENT',
  // 12: 'IMAGE',
  // 14: 'CROSS_APPLICATION_STATUS_TRACKING',
  // 16: 'MATRIX',
  19: 'IP_ADDRESS',
  // 20: 'RECORD_STATUS',
  21: 'FIRST_PUBLISHED',
  22: 'LAST_UPDATED'
  // 23: 'RELATED_RECORD',
  // 24: 'SUB_FORM',
  // 25: 'HISTORY_LOG',
  // 26: 'DISCUSSION',
  // 27: 'MULTIPLE_REFERENCE_DISPLAY_CONTROL',
  // 28: 'QUESTIONNAIRE_REFERENCE',
  // 29: 'ACCESS_HISTORY',
  // 30: 'VOTING',
  // 31: 'SCHEDULER'
};

module.exports = getDetailFields;
