TARGET := target

.PHONY: package clean

package:
	dpkg-buildpackage -us -uc -b
	mkdir -p $(TARGET)
	mv ../luks-enroll_*.deb ../luks-enroll_*.buildinfo ../luks-enroll_*.changes $(TARGET)/

clean:
	rm -rf $(TARGET)
