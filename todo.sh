#!/bin/bash

pushd ~/Library/Calendars > /dev/null

if [ -e /tmp/todo ]; then
	nr_files=$(find . -newer /tmp/todo -exec grep -rlI VTODO {} \+ | wc -l)
	if [ $nr_files == 0 ]; then
		cat /tmp/todo
		exit
	fi

	# empty todo file
	rm /tmp/todo
fi

filenames=$(grep -rlI VTODO *)
while read -r filename; do
	if grep -q "STATUS:COMPLETED" $filename; then
		continue
	fi
	summary=$(grep "SUMMARY:" $filename | cut -d : -f 2-)


	info=$(dirname $(dirname $filename))/info.plist
	title=$(defaults read ~/Library/Calendars/$info Title)

	echo "* $title: $summary" >> /tmp/todo

done <<< "$filenames"

# output todo file
cat /tmp/todo
popd > /dev/null
