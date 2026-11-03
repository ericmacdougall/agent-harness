package main

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"
)

const providerWriteLimit = 2 << 20
const providerWriteTimeout = 5 * time.Second

type inputAdmission func() (func(), error)
type inputFrame struct {
	admit inputAdmission
	ctx   context.Context
	data  []byte
	done  chan error
}
type inputWriter struct {
	input  io.WriteCloser
	queue  chan inputFrame
	closed chan struct{}
	once   sync.Once
}

func newInputWriter(input io.WriteCloser) *inputWriter {
	w := &inputWriter{input: input, queue: make(chan inputFrame, 16), closed: make(chan struct{})}
	go w.loop()
	return w
}
func (w *inputWriter) close() { w.once.Do(func() { close(w.closed); _ = w.input.Close() }) }
func (w *inputWriter) loop() {
	for {
		select {
		case <-w.closed:
			return
		case frame := <-w.queue:
			select {
			case <-frame.ctx.Done():
				frame.done <- errors.New("provider write cancelled before dispatch")
				continue
			default:
			}
			var release func()
			var admissionErr error
			if frame.admit != nil {
				release, admissionErr = frame.admit()
			}
			if admissionErr != nil {
				frame.done <- admissionErr
				continue
			}
			n, err := w.input.Write(frame.data)
			if err == nil && n != len(frame.data) {
				err = io.ErrShortWrite
			}
			if release != nil {
				release()
			}
			frame.done <- err
			if err != nil {
				w.close()
				return
			}
		}
	}
}
func (w *inputWriter) write(ctx context.Context, data []byte) error {
	return w.writeAdmitted(ctx, data, nil)
}
func (w *inputWriter) writeAdmitted(ctx context.Context, data []byte, admit inputAdmission) error {
	if len(data) > providerWriteLimit {
		return errors.New("provider input exceeds 2 MiB")
	}
	bounded, cancel := context.WithTimeout(ctx, providerWriteTimeout)
	defer cancel()
	frame := inputFrame{admit: admit, ctx: bounded, data: data, done: make(chan error, 1)}
	select {
	case <-w.closed:
		return errors.New("provider input is closed")
	case <-bounded.Done():
		return errors.New("provider write deadline before dispatch")
	case w.queue <- frame:
	}
	select {
	case err := <-frame.done:
		return err
	case <-w.closed:
		return errors.New("provider input closed; write outcome unknown")
	case <-bounded.Done():
		w.close()
		return errors.New("provider input blocked; write outcome unknown")
	}
}
