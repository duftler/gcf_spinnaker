// Open issues:
//  - How to render creationTimestamp in user's timezone (and same format as 'Activity Feed'?) so it matches the rest of pantheon?
//  - Any way to publish via protoPayload instead of textPayload? (This would maybe let us eventually publish actual 'Google Cloud Audit Logging' 'Admin Activity' log entries.)
//  - Any equivalent to console.debug()?

const config = require('./config.json');
const moment = require('moment-timezone');

/**
 * Logs Spinnaker events to Stackdriver Logging.
 *
 * @param {!Object} req Cloud Function request context.
 * @param {!Object} res Cloud Function response context.
 */
exports.spinnakerAuditLog = function spinnakerAuditLog (req, res) {
  console.warn('** req.body.payload=' + JSON.stringify(req.body.payload));

  try {
    verifyWebhook(req.get('authorization') || '');

    if (req.body.eventName !== 'spinnaker_events' || req.body.payload === undefined) {
      res.status(400).send('Spinnaker audit log request body is malformed.');
    } else {
      var content = req.body.payload.content;
      var eventSource = req.body.payload.details.source;
      var eventType = req.body.payload.details.type;
      var execution = content.execution;
      var context = content.context;
      var user = execution && execution.authentication && execution.authentication.user ? execution.authentication.user : 'n/a';

      if (execution && execution.trigger && execution.trigger.runAsUser) {
        user = execution.trigger.runAsUser;
      }

      var creationTimestamp = moment.tz(Number(req.body.payload.details.created), config.TIMEZONE).format('ddd, DD MMM YYYY HH:mm:ss z');

      var reasonSegment;
      if (eventSource === 'igor') {
        if (eventType === 'build') {
          var lastBuild = content.project.lastBuild;
          var jenkinsTimestamp = moment.tz(Number(lastBuild.timestamp), config.TIMEZONE).format('ddd, DD MMM YYYY HH:mm:ss z');

          console.log('Spinnaker: Jenkins project ' + content.project.name + ' successfully completed build #' + lastBuild.number + ' at ' + jenkinsTimestamp + '.');
        } else if (eventType === 'docker') {
          console.log('Spinnaker: Docker tag ' + content.tag + ' was pushed to repository ' + content.repository + ' in registry ' + content.registry + ' at ' + creationTimestamp + '.');
        }
      } else if (eventType === 'git') {
        console.log('Spinnaker: Received webhook for project ' + content.slug + ' in org ' + content.repoProject + ' from ' + eventSource + ' at commit ' + content.hash + ' on branch ' + content.branch + ' at ' + creationTimestamp + '.');
      } else if (eventType === 'orca:stage:starting' && !context.stageDetails.isSynthetic) {
        if (!content.standalone) {
          console.log('Spinnaker: User ' + user + ' executed operation ' + context.stageDetails.name + ' (of type ' + context.stageDetails.type + ') via pipeline ' + execution.name + ' of application ' + execution.application + ' at ' + creationTimestamp + '.');
        } else {
          reasonSegment = context.reason ? ' for reason "' + context.reason + '"' : '';

          console.log('Spinnaker: User ' + user + ' executed ad-hoc operation ' + execution.stages[0].type + ' (' + execution.description + ')' + reasonSegment + ' at ' + creationTimestamp + '.');
        }
      } else if (eventType === 'orca:pipeline:starting') {
        var parametersSegment = execution.trigger.parameters ? ' (with parameters ' + JSON.stringify(execution.trigger.parameters) + ')' : '';

        console.log('Spinnaker: User ' + user + ' executed pipeline ' + execution.name + ' of application ' + execution.application + ' via ' + execution.trigger.type + ' trigger' + parametersSegment + ' at ' + creationTimestamp + '.');
      } else if (eventType === 'orca:pipeline:failed' && execution.canceled) {
        var cancellationUser = execution.canceledBy ? execution.canceledBy : null;

        if (cancellationUser) {
          reasonSegment = execution.cancellationReason ? ' for reason "' + execution.cancellationReason + '"' : '';

          console.log('Spinnaker: User ' + cancellationUser + ' canceled pipeline ' + execution.name + ' of application ' + execution.application + reasonSegment + ' at ' + creationTimestamp + '.');
        } else {
          console.log('Spinnaker: Pipeline ' + execution.name + ' of application ' + execution.application + ' failed at ' + creationTimestamp + '.');
        }
      } else if (eventType === 'orca:pipeline:complete') {
        console.log('Spinnaker: Pipeline ' + execution.name + ' of application ' + execution.application + ' completed at ' + creationTimestamp + '.');
      } else if (!content.standalone && context && context.stageDetails && context.stageDetails.type === 'manualJudgment' && eventType === 'orca:stage:failed') {
        console.log('Spinnaker: User ' + context.lastModifiedBy + ' judged stage ' + context.stageDetails.name + ' of pipeline ' + execution.name + ' to stop at ' + creationTimestamp + '.');
      } else if (!content.standalone && context && context.stageDetails && context.stageDetails.type === 'manualJudgment' && eventType === 'orca:stage:complete') {
        var judgmentInputSegment = context.judgmentInput ? ' (judgment "' + context.judgmentInput + '" was selected)' : '';

        console.log('Spinnaker: User ' + context.lastModifiedBy + ' judged stage ' + context.stageDetails.name + ' of pipeline ' + execution.name + ' of application ' + execution.application + ' to continue' + judgmentInputSegment + ' at ' + creationTimestamp + '.');
      } else if (eventType === 'orca:task:failed') {
        var failureReasonSegment = context.exception && context.exception.details && context.exception.details.errors && context.exception.details.errors[0] ? ' due to ' + JSON.stringify(context.exception.details.errors) : '';

        if (!content.standalone) {
          console.log('Spinnaker: Operation ' + context.stageDetails.name + ' (of type ' + context.stageDetails.type + ') of pipeline ' + execution.name + ' of application ' + execution.application + ' failed' + failureReasonSegment + ' at ' + creationTimestamp + '.');        
        } else {
          console.log('Spinnaker: Ad-hoc operation ' + context.stageDetails.type + ' failed' + failureReasonSegment + ' at ' + creationTimestamp + '.');
        }
      }

      res.status(200).send('Success: ' + req.body.eventName);
    }
  } catch (err) {
    console.error(err);
    res.status(err.code || 500).send(err);
  }
};

/**
 * Verify that the webhook request came from spinnaker/echo.
 *
 * @param {string} authorization The authorization header of the request, e.g. "Basic ZmdvOhJhcg=="
 */
function verifyWebhook (authorization) {
  const basicAuth = new Buffer(authorization.replace('Basic ', ''), 'base64').toString();
  const parts = basicAuth.split(':');

  if (parts[0] !== config.USERNAME || parts[1] !== config.PASSWORD) {
    const error = new Error('Invalid credentials');
    error.code = 401;
    throw error;
  }
}
