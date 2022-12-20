const url = 'https://www.example.com/something/something/';
const LOG_URL = 'https://log-service.example.com/'; // havent tested this yet

const body = {
  results: ['default data to send'],
  errors: null,
  msg: 'I sent this to the fetch',
};

/**
 * gatherResponse awaits and returns a response body as a string.
 * Use await gatherResponse(..) in an async function to get the response body
 * @param {Response} response
 */
async function gatherResponse(response) {
  const { headers } = response;
  const contentType = headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    return JSON.stringify(await response.json());
  } else if (contentType.includes('application/text')) {
    return response.text();
  } else if (contentType.includes('text/html')) {
    return response.text();
  } else {
    return response.text();
  }
}

async function handleRequest() {
  const init = {
    body: JSON.stringify(body),
    method: 'POST',
    headers: {
      'content-type': 'application/json;charset=UTF-8',
      // "cf-worker"	: "del.workers.dev"  this doesnt work it is filtered
    },
    // Change a Cloudflare feature on the outbound responses to disable messing with our request
    // https://developers.cloudflare.com/workers/runtime-apis/request/#requestinitcfproperties
    cf: {
      apps: false,
      scrapeShield: false,
      webp: false,
      polish: "off",
      mirage: false,
      minify: false,
      // resolveOverride: "anotherdomain"
    },
  };
  const response = await fetch(url, init);
  const results = await gatherResponse(response);
  return new Response(results, init);
}

addEventListener('fetch', event => {
  // Have any uncaught errors thrown go directly to origin
  event.passThroughOnException();
  return event.respondWith(handleRequest());
});

// The reason this is here is so that we can prolong our queries
// if the worker hasnt get response in 3 seconds it fails the request
// however logging requests seem to have longer thresholds
// NOTE: Havent used it yet
async function handleRequestWithLogging(event) {
  let response;

  try {
    response = await fetch(event.request);
    if (!response.ok && !response.redirected) {
      const body = await response.text();
      throw new Error(
        'Bad response at origin. Status: ' +
          response.status +
          ' Body: ' +
          // Ensure the string is small enough to be a header
          body.trim().substring(0, 10)
      );
    }
  } catch (err) {
    // Without event.waitUntil(), your fetch() to Cloudflare's
    // logging service may or may not complete
    event.waitUntil(postLog(err.toString()));
    const stack = JSON.stringify(err.stack) || err;

    // Copy the response and initialize body to the stack trace
    response = new Response(stack, response);

    // Add the error stack into a header to find out what happened
    response.headers.set('X-Debug-stack', stack);
    response.headers.set('X-Debug-err', err);
  }
  return response;
}
function postLog(data) {
  return fetch(LOG_URL, {
    method: 'POST',
    body: data,
  });
}
