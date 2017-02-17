const config = require('./config.json');
const moment = require('moment-timezone');
const logging = require('@google-cloud/logging')({projectId: config.PROJECT_ID, credentials: require(config.CREDENTIALS_PATH)});

/**
 * Logs Spinnaker events to Stackdriver Logging.
 *
 * @param {!Object} req Cloud Function request context.
 * @param {!Object} res Cloud Function response context.
 */
exports.spinnakerAuditLog = function spinnakerAuditLog (req, res) {
  log('req.body.payload=' + JSON.stringify(req.body.payload), null, null, 'debug');

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

          if (lastBuild.result === 'SUCCESS') {
            log('Spinnaker: Jenkins project ' + content.project.name + ' successfully completed build #' + lastBuild.number + ' at ' + jenkinsTimestamp + '.', null, null);
          } else {
            log('Spinnaker: Jenkins project ' + content.project.name + ' completed build #' + lastBuild.number + ' with status ' + lastBuild.result + ' at ' + jenkinsTimestamp + '.', null, null, 'error');
          }
        } else if (eventType === 'docker') {
          log('Spinnaker: Docker tag ' + content.tag + ' was pushed to repository ' + content.repository + ' in registry ' + content.registry + ' at ' + creationTimestamp + '.', null, null);
        }
      } else if (eventType === 'git') {
        log('Spinnaker: Received webhook for project ' + content.slug + ' in org ' + content.repoProject + ' from ' + eventSource + ' at commit ' + content.hash + ' on branch ' + content.branch + ' at ' + creationTimestamp + '.', null, null);
      } else if (eventType === 'orca:stage:starting' && !context.stageDetails.isSynthetic) {
        if (!content.standalone) {
          log('Spinnaker: User ' + user + ' executed operation ' + context.stageDetails.name + ' (of type ' + context.stageDetails.type + ') via pipeline ' + execution.name + ' of application ' + execution.application + ' at ' + creationTimestamp + '.', execution.application, execution.name);
        } else {
          reasonSegment = context.reason ? ' for reason "' + context.reason + '"' : '';

          log('Spinnaker: User ' + user + ' executed ad-hoc operation ' + execution.stages[0].type + ' (' + execution.description + ')' + reasonSegment + ' at ' + creationTimestamp + '.', null, null);
        }
      } else if (eventType === 'orca:pipeline:starting') {
        var parametersSegment = execution.trigger.parameters ? ' (with parameters ' + JSON.stringify(execution.trigger.parameters) + ')' : '';

        log('Spinnaker: User ' + user + ' executed pipeline ' + execution.name + ' of application ' + execution.application + ' via ' + execution.trigger.type + ' trigger' + parametersSegment + ' at ' + creationTimestamp + '.', execution.application, execution.name);
      } else if (eventType === 'orca:pipeline:failed' && execution.canceled) {
        var cancellationUser = execution.canceledBy ? execution.canceledBy : null;

        if (cancellationUser) {
          reasonSegment = execution.cancellationReason ? ' for reason "' + execution.cancellationReason + '"' : '';

          log('Spinnaker: User ' + cancellationUser + ' canceled pipeline ' + execution.name + ' of application ' + execution.application + reasonSegment + ' at ' + creationTimestamp + '.', execution.application, execution.name, 'warning');
        } else {
          log('Spinnaker: Pipeline ' + execution.name + ' of application ' + execution.application + ' failed at ' + creationTimestamp + '.', execution.application, execution.name, 'error');
        }
      } else if (eventType === 'orca:pipeline:complete') {
        log('Spinnaker: Pipeline ' + execution.name + ' of application ' + execution.application + ' completed at ' + creationTimestamp + '.', execution.application, execution.name);
      } else if (!content.standalone && context && context.stageDetails && context.stageDetails.type === 'manualJudgment' && eventType === 'orca:stage:failed') {
        log('Spinnaker: User ' + context.lastModifiedBy + ' judged stage ' + context.stageDetails.name + ' of pipeline ' + execution.name + ' of application ' + execution.application + ' to stop at ' + creationTimestamp + '.', execution.application, execution.name, 'warning');
      } else if (!content.standalone && context && context.stageDetails && context.stageDetails.type === 'manualJudgment' && eventType === 'orca:stage:complete') {
        var judgmentInputSegment = context.judgmentInput ? ' (judgment "' + context.judgmentInput + '" was selected)' : '';

        log('Spinnaker: User ' + context.lastModifiedBy + ' judged stage ' + context.stageDetails.name + ' of pipeline ' + execution.name + ' of application ' + execution.application + ' to continue' + judgmentInputSegment + ' at ' + creationTimestamp + '.');
      } else if (eventType === 'orca:task:failed') {
        var failureReasonSegment = context.exception && context.exception.details && context.exception.details.errors && context.exception.details.errors[0] ? ' due to ' + JSON.stringify(context.exception.details.errors) : '';

        if (!content.standalone) {
          log('Spinnaker: Operation ' + context.stageDetails.name + ' (of type ' + context.stageDetails.type + ') of pipeline ' + execution.name + ' of application ' + execution.application + ' failed' + failureReasonSegment + ' at ' + creationTimestamp + '.', execution.application, execution.name, 'error');
        } else {
          log('Spinnaker: Ad-hoc operation ' + context.stageDetails.type + ' failed' + failureReasonSegment + ' at ' + creationTimestamp + '.', null, null, 'error');
        }
      }

      res.status(200).send('Success: ' + req.body.eventName);
    }
  } catch (err) {
    log(err, 'error');
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

/**
 * Writes message to StackDriver with specified severity.
 * 
 * @param {string} message - The message to log to StackDriver logging.
 * @param {('alert', 'critical', 'debug', 'emergency', 'error', 'info', 'notice', 'warning', 'write')} severity - The 
 * severity of the logged message. Defaults to 'info'.
 */
function log(message, application, pipeline, severity = 'info') {
  var log = logging.log(config.AUDIT_LOG_NAME);
  var metadata = {resource: {type: 'cloud_function'}};
  var jsonPayload = {message: message};
  if (application) {
    jsonPayload.application = application;
  }
  if (pipeline) {
    jsonPayload.pipeline = pipeline;
  }
  var entry = log.entry(metadata, jsonPayload);
  
  log[severity](entry, function() {});
}
