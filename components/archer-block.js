polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  getDetailFieldsErrorMessage: {},
  getDetailFieldsIsRunning: {},
  expandableTitleStates: {},
  detailFieldsStates: {},
  getDetailFields: function (index, ContentId) {
    const outerThis = this;

    outerThis.set(
      'getDetailFieldsErrorMessage',
      Object.assign({}, outerThis.get('getDetailFieldsErrorMessage'), { [index]: '' })
    );
    outerThis.set(
      'getDetailFieldsIsRunning',
      Object.assign({}, outerThis.get('getDetailFieldsIsRunning'), { [index]: true })
    );

    outerThis
      .sendIntegrationMessage({ action: 'getDetailFields', data: { ContentId } })
      .then(({ detailFields }) => {
        outerThis.set(
          'detailFieldsStates',
          Object.assign({}, outerThis.get('detailFieldsStates'), {
            [index]: detailFields
          })
        );
        outerThis.set(
          'expandableTitleStates',
          Object.assign({}, outerThis.get('expandableTitleStates'), { [index]: true })
        );
      })
      .catch((err) => {
        outerThis.set(
          `getDetailFieldsErrorMessage`,
          Object.assign({}, outerThis.get('getDetailFieldsErrorMessage'), {
            [index]:
              (err &&
                (err.detail || err.err || err.message || err.title || err.description)) ||
              'Unknown Reason'
          })
        );
      })
      .finally(() => {
        outerThis.set(
          'getDetailFieldsIsRunning',
          Object.assign({}, outerThis.get('getDetailFieldsIsRunning'), { [index]: false })
        );
        outerThis.get('block').notifyPropertyChange('data');
        setTimeout(() => {
          if (outerThis.get(`getDetailFieldsErrorMessage.${index}`)) {
            outerThis.set(
              `getDetailFieldsErrorMessage`,
              Object.assign({}, outerThis.get('getDetailFieldsErrorMessage'), {
                [index]: ''
              })
            );
            outerThis.set(
              `expandableTitleStates`,
              Object.assign({}, outerThis.get('expandableTitleStates'), {
                [index]: false
              })
            );
          }
          outerThis.get('block').notifyPropertyChange('data');
        }, 5000);
      });
  },
  actions: {
    toggleExpandableTitle: function (index, ContentId) {
      this.set(
        `expandableTitleStates`,
        Object.assign({}, this.get('expandableTitleStates'), {
          [index]: !this.get('expandableTitleStates')[index]
        })
      );
      if (!this.get('detailFieldsStates')[index]) this.getDetailFields(index, ContentId);

      this.get('block').notifyPropertyChange('data');
    }
  }
});
