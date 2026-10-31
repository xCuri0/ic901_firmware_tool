# IC901 Firmware Tool
Patch firmware on IC901/UG901 XP-Pen/Ugee drawing tablets to increase report rate and control smoothing.

Most tablets should be capable of atleast 500hz with minimal jitter while having working pressure/buttons/tilt and other functionality.

## Checking if tablet is supported
XP-Pen/Ugee tablets have multiple revisions using the same name, so just knowing the model is useless.

Download **xppen-tools** from [https://github.com/NiceAesth/xppen-tools-builds/releases](https://github.com/NiceAesth/xppen-tools-builds/releases)

Run ```xppen-tools info```, it should output something like this.

```
[INFO] Runtime device: 4 inch PenTablet [28BD:0913]
[INFO] Identity: manufacturer=UGTABLET serial=000000
[INFO] Firmware: UG901_BPU0401 (19-07-25_Release01)
```
> output above is from XP-Pen G430S_B (2019) with `UG901`

It should contain `UG901` or `IC901`, if not then your tablet likely uses a different chip.

## Dumping firmware
Enter DFU mode using `xppen-tools dfu`.

After this run `xppen-tools dump backup`, **it will take 10-15 minutes to finish.** A copy of current firmware will be saved in a folder named `backup`.

Unlike some other manufacturers XP-Pen/Ugee doesn't make stock firmware readily available so keep copies and/or upload it for others.

## Usage
Python should be installed and added to PATH.

Run `python -m pip install -r requirements.txt` to install required packages.

## Generating patched firmware
Copy `ic901-code.bin` from the backup folder mentioned earlier. **Only use stock unmodified firmware files**

```
python ic901_firmware_tool.py ic901-code.bin --save-cfg fw-ic901.ini
```

Current firmware config should now be in `fw-ic901.ini`, edit that file to adjust it.

After you've edited `fw-ic901.ini` patch firmware with those settings using

```
python ic901_firmware_tool.py ic901-code.bin --patch-cfg fw-ic901.ini --output ic901-code-patched.bin
```
The output filename should start with `ic901-code`, otherwise `xppen-tools` might not recognize it when generating `.hex`

If you can, check the patched difference compared with stock using preferred disassembler to make sure everything looks good.

Assuming there's no issues, generate a `.hex` which can be flashed using `xppen-tools`.

```
xppen-tools ihex --ic 901 ic901-code-patched.bin -o ic901-code-patched.hex
```

## Flashing firmware
Enter DFU mode using ```xppen-tools dfu```.

To flash the new firmware run
```
xppen-tools update ic901-code-patched.hex
```
Don't disconnect or close window while it's flashing.

After flashing it should automatically exit DFU mode, use OTD Tablet Debugger or any report rate checker to confirm it's working.

If anything goes wrong during flashing don't try to exit DFU mode or disconnect/power-off, instead flash stock firmware which you can generate a `.hex` for using same method as above.

## Disclaimer
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
