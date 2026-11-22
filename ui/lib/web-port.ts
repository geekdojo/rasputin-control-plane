// The WEB PORT field on the two custom-app forms (geekdojo/geekdojo-brain#1090):
// the create drawer on the App Catalog page and the EDIT COMPOSE modal.
//
// The field holds the port on the node (127.0.0.1) that the app's Compose file
// publishes, the host side of a `ports:` mapping, and it is sent as the
// contract's `webPort` (#1089). The api is the one validator: this module only
// turns the field's text into the value to send, and never decides whether a
// port is acceptable, so its range rule and its sentence live in one place.

/**
 * The `webPort` to send for the field's text.
 *
 *   - empty or whitespace only: undefined, so the key is left out of the body
 *     and the request is the same as one from a form with no field;
 *   - text Number() reads as a finite number: that number, as typed. 0, -1,
 *     80.5 and 70000 are sent unchanged for the api to refuse;
 *   - anything else: the trimmed text, so the api refuses it in its own words.
 *
 * It never returns NaN: JSON.stringify(NaN) is null, which the api reads as
 * "no port", and the owner would get an app with no port and no error.
 */
export function webPortValue(text: string): number | string | undefined {
  const t = text.trim();
  if (t === '') return undefined;
  const n = Number(t);
  return Number.isFinite(n) ? n : t;
}

/** The field's label on both forms. */
export const WEB_PORT_LABEL = 'WEB PORT (PUBLISHED ON THE NODE)';

/** What the port is, on both forms. Each form adds what an empty field means. */
export const WEB_PORT_MEANING =
  "The port your Compose file publishes on 127.0.0.1 for this app's web page, such as 8080 in 127.0.0.1:8080:80. It is not the container's port.";

/** On create, an empty field means the app has no web page. */
export const WEB_PORT_EMPTY_ON_CREATE = 'Leave it empty if the app has no web page.';

/** On edit, an empty field keeps the stored port: no request removes one. */
export const WEB_PORT_EMPTY_ON_EDIT = 'Leave it empty to keep the current port.';
