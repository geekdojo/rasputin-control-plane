// F-988-12: the sign-in pages render the default token set whichever console
// theme an administrator picks, so every colour in the theme's CSS is a
// var(--rasp-*) token from ui/styles/tokens.css and nothing else
// (geekdojo/geekdojo-brain#988). This finds the colours that are not.

// CSS's named colours (CSS Color 4), which a colour property could name
// instead of a token.
const NAMED = new Set(
  (
    'aliceblue antiquewhite aqua aquamarine azure beige bisque black blanchedalmond blue blueviolet brown burlywood ' +
    'cadetblue chartreuse chocolate coral cornflowerblue cornsilk crimson cyan darkblue darkcyan darkgoldenrod darkgray ' +
    'darkgreen darkgrey darkkhaki darkmagenta darkolivegreen darkorange darkorchid darkred darksalmon darkseagreen ' +
    'darkslateblue darkslategray darkslategrey darkturquoise darkviolet deeppink deepskyblue dimgray dimgrey dodgerblue ' +
    'firebrick floralwhite forestgreen fuchsia gainsboro ghostwhite gold goldenrod gray green greenyellow grey honeydew ' +
    'hotpink indianred indigo ivory khaki lavender lavenderblush lawngreen lemonchiffon lightblue lightcoral lightcyan ' +
    'lightgoldenrodyellow lightgray lightgreen lightgrey lightpink lightsalmon lightseagreen lightskyblue lightslategray ' +
    'lightslategrey lightsteelblue lightyellow lime limegreen linen magenta maroon mediumaquamarine mediumblue ' +
    'mediumorchid mediumpurple mediumseagreen mediumslateblue mediumspringgreen mediumturquoise mediumvioletred ' +
    'midnightblue mintcream mistyrose moccasin navajowhite navy oldlace olive olivedrab orange orangered orchid ' +
    'palegoldenrod palegreen paleturquoise palevioletred papayawhip peru pink plum powderblue purple rebeccapurple red ' +
    'rosybrown royalblue saddlebrown salmon seagreen seashell sienna silver skyblue slateblue slategray slategrey snow ' +
    'springgreen steelblue tan teal thistle tomato turquoise violet wheat white whitesmoke yellow yellowgreen ' +
    'canvas canvastext linktext visitedtext activetext buttonface buttontext field fieldtext highlight highlighttext graytext'
  ).split(' '),
);

const COLOUR_FUNCTIONS = /\b(rgba?|hsla?|hwb|lab|lch|oklab|oklch|color|color-mix)\(\s*([^,)\s]+)/gi;

/** "file:line: …" for each hard-coded colour in a style sheet. */
export function hardCodedColours(file: string, css: string): string[] {
  const out: string[] = [];
  const text = css.replace(/\/\*[\s\S]*?\*\//g, (c) => c.replace(/[^\n]/g, ' '));
  text.split('\n').forEach((line, i) => {
    const where = `${file}:${i + 1}`;
    for (const m of line.matchAll(/#[0-9a-fA-F]{3,8}\b/g)) out.push(`${where}: the hex colour ${m[0]}`);
    for (const m of line.matchAll(COLOUR_FUNCTIONS)) {
      if (!m[2].startsWith('var(')) out.push(`${where}: ${m[1]}() with a literal channel (${m[2]})`);
    }
    const decl = /^\s*([a-z-]+)\s*:\s*(.+?);?\s*$/i.exec(line);
    if (decl) {
      for (const word of decl[2].replace(/url\([^)]*\)|var\([^)]*\)|'[^']*'|"[^"]*"/g, ' ').toLowerCase().split(/[\s,()/]+/)) {
        if (NAMED.has(word)) out.push(`${where}: the named colour ${word} in ${decl[1]}`);
      }
    }
  });
  return out;
}
