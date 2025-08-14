/* See LICENSE file for copyright and license details.
 *
 * This is largely adapted from DWM, the dynamic window manager by 
 * suckless.org, originally licensed under the MIT license.
 */
#define MAX(A, B)               ((A) > (B) ? (A) : (B))
#define MIN(A, B)               ((A) < (B) ? (A) : (B))
#define BETWEEN(X, A, B)        ((A) <= (X) && (X) <= (B))
#define LENGTH(X)               (sizeof (X) / sizeof (X)[0])

void die(const char *fmt, ...);
